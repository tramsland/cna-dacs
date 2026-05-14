#Requires -Version 5.1
# Remote Service Status Checker (Parallel with Logging)
# Checks Tomcat, Content Server, and Content Server Admin on remote Windows servers
# Includes Log4j vulnerability scanner for Tomcat webapps and CS webservices directories
# v3.1 -- log4j scanner added

#region Parameters
param(
    [switch]$QuietOK,
    [string]$SmtpServer          = "smtp.domain.com",
    [string]$EmailFrom           = "monitoring@domain.com",
    [string]$EmailTo             = "ops@domain.com",
    [string]$TeamsWebhookUrl     = "",
    [switch]$AutoRestartStopped,
    [int]$InformantWarnMs        = 5000,
    [int]$MaxParallelJobs        = 10,

    # Log4j: flag anything below this version as VULNERABLE
    # Log4j 2.x latest is 2.24.3 — set your org standard here
    [string]$Log4jMinSafeVersion = "2.17.1"
)
#endregion

#region Configuration
$configFile = Join-Path $PSScriptRoot "servers.txt"
if (-not (Test-Path $configFile)) {
    Write-Host "ERROR: Server config file not found: $configFile" -ForegroundColor Red
    Write-Host "Create a servers.txt file in the same directory as this script," -ForegroundColor Yellow
    Write-Host "with one server FQDN per line. Lines starting with # are comments." -ForegroundColor Yellow
    Write-Host "Group servers with [ZoneName] section headers." -ForegroundColor Yellow
    exit 1
}

$serverGroups = [ordered]@{}
$currentGroup = "Ungrouped"
foreach ($line in (Get-Content $configFile)) {
    $trimmed = $line.Trim()
    if ($trimmed -match '^\s*$' -or $trimmed -match '^\s*#') { continue }
    if ($trimmed -match '^\[(.+)\]$') {
        $currentGroup = $Matches[1].Trim()
        if (-not $serverGroups.Contains($currentGroup)) {
            $serverGroups[$currentGroup] = New-Object System.Collections.Generic.List[string]
        }
        continue
    }
    if (-not $serverGroups.Contains($currentGroup)) {
        $serverGroups[$currentGroup] = New-Object System.Collections.Generic.List[string]
    }
    $serverGroups[$currentGroup].Add($trimmed)
}

$serverCount = ($serverGroups.Values | Measure-Object -Property Count -Sum).Sum
if ($serverCount -eq 0) {
    Write-Host "ERROR: No servers found in $configFile" -ForegroundColor Red
    exit 1
}

$timestamp        = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile          = Join-Path $PSScriptRoot ("ServiceCheck_" + $timestamp + ".log")
$csvFile          = Join-Path $PSScriptRoot ("ServiceCheck_" + $timestamp + ".csv")
$htmlFile         = Join-Path $PSScriptRoot ("ServiceCheck_" + $timestamp + ".html")
$webTimeoutSec    = 45
$jobTimeoutSec    = 300
$eventLogCount    = 5
$portCheckTimeout = 3
#endregion

#region Host-side helpers
function Write-Log {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
    Add-Content -Path $logFile -Value $Message
}

function HtmlEncode {
    param([string]$s)
    if (-not $s) { return "" }
    $s = $s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace('"',"&quot;")
    return $s
}

function Get-VisualBar {
    param([double]$Percent, [int]$Width = 20)
    $filled = [math]::Round($Percent / (100 / $Width))
    return ("[" + ("#" * $filled).PadRight($Width, "-") + "]")
}

function Get-ThresholdTag {
    param([double]$Percent)
    if ($Percent -ge 90) { return " [CRITICAL]" }
    if ($Percent -ge 75) { return " [WARN]" }
    return ""
}

function Send-TeamsAlert {
    param([string]$WebhookUrl, [string]$Title, [string]$Body)
    if (-not $WebhookUrl) { return }
    $payload = @{
        type        = "message"
        attachments = @(@{
            contentType = "application/vnd.microsoft.card.adaptive"
            content     = @{
                '$schema' = "http://adaptivecards.io/schemas/adaptive-card.json"
                type      = "AdaptiveCard"
                version   = "1.4"
                body      = @(
                    @{ type = "TextBlock"; size = "Medium"; weight = "Bolder"; text = $Title }
                    @{ type = "TextBlock"; text = $Body; wrap = $true }
                )
            }
        })
    } | ConvertTo-Json -Depth 10
    try {
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload `
            -ContentType "application/json" -ErrorAction Stop | Out-Null
    } catch {
        Write-Log "Teams webhook failed: $_" -Color Red
    }
}
#endregion

#region Log4j scanner scriptblock
# ─────────────────────────────────────────────────────────────────────────────
# Scans one or more directories recursively for log4j jar files.
# For each jar found it:
#   1. Tries to parse the version from the filename  (log4j-core-2.17.1.jar)
#   2. Opens the jar and reads META-INF/maven/.../pom.properties for the
#      canonical version — more reliable than filename alone.
#   3. Compares the version against $MinSafeVersion using [version] cast.
#   4. Returns a list of result objects with Path, Version, Source, Status.
# ─────────────────────────────────────────────────────────────────────────────
$log4jScanBlock = {
    param(
        [string[]]$ScanRoots,
        [string]$MinSafeVersion
    )

    $findings = New-Object "System.Collections.Generic.List[PSObject]"

    # Helper: compare two dotted version strings safely
    function Compare-Version {
        param([string]$v1, [string]$v2)
        try {
            $a = New-Object System.Version $v1
            $b = New-Object System.Version $v2
            return $a.CompareTo($b)   # <0 means v1 < v2
        } catch {
            return [string]::Compare($v1, $v2)
        }
    }

    # Helper: extract version from pom.properties inside a jar
    function Get-VersionFromJar {
        param([string]$JarPath)
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($JarPath)
            # pom.properties lives at:
            #   META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties
            # but we search broadly in case the groupId path differs
            $pomEntry = $zip.Entries | Where-Object {
                $_.FullName -like "META-INF/maven/*log4j*/pom.properties"
            } | Select-Object -First 1

            if ($pomEntry) {
                $reader  = New-Object System.IO.StreamReader($pomEntry.Open())
                $content = $reader.ReadToEnd()
                $reader.Close()
                $zip.Dispose()
                if ($content -match '(?m)^version\s*=\s*(.+)$') {
                    return $Matches[1].Trim()
                }
            } else {
                # Fall back: check MANIFEST.MF Implementation-Version
                $mfEntry = $zip.Entries | Where-Object {
                    $_.FullName -eq "META-INF/MANIFEST.MF"
                } | Select-Object -First 1
                if ($mfEntry) {
                    $reader  = New-Object System.IO.StreamReader($mfEntry.Open())
                    $content = $reader.ReadToEnd()
                    $reader.Close()
                    $zip.Dispose()
                    if ($content -match 'Implementation-Version:\s*(.+)') {
                        return $Matches[1].Trim()
                    }
                }
            }
            $zip.Dispose()
        } catch { }
        return $null
    }

    foreach ($root in $ScanRoots) {
        if (-not $root -or -not (Test-Path $root)) {
            $findings.Add([PSCustomObject]@{
                ScanRoot   = $root
                Path       = $root
                FileName   = ""
                Version    = "N/A"
                VersionSrc = "N/A"
                Status     = "SCAN_ROOT_NOT_FOUND"
                IsVulnerable = $false
            })
            continue
        }

        # Find all log4j jars — both log4j-*.jar and log4j*.jar patterns
        $jars = @(Get-ChildItem -Path $root -Recurse -Filter "log4j*.jar" -ErrorAction SilentlyContinue |
                  Where-Object { -not $_.PSIsContainer })

        if ($jars.Count -eq 0) {
            $findings.Add([PSCustomObject]@{
                ScanRoot     = $root
                Path         = $root
                FileName     = ""
                Version      = "N/A"
                VersionSrc   = "N/A"
                Status       = "NOT_FOUND"
                IsVulnerable = $false
            })
            continue
        }

        foreach ($jar in $jars) {
            # Try jar-internal version first (most reliable)
            $jarVersion = Get-VersionFromJar -JarPath $jar.FullName
            $versionSrc = if ($jarVersion) { "pom.properties" } else { "filename" }

            # Fall back to filename parsing:  log4j-core-2.17.1.jar  or  log4j-2.17.1.jar
            if (-not $jarVersion) {
                if ($jar.Name -match 'log4j[^-]*-(\d+\.\d+[\.\d]*)\.jar') {
                    $jarVersion = $Matches[1]
                }
            }

            if (-not $jarVersion) {
                $jarVersion = "UNKNOWN"
                $versionSrc = "undetectable"
            }

            # Determine vulnerability status
            $isVulnerable = $false
            $status       = "OK"

            if ($jarVersion -eq "UNKNOWN") {
                $status = "UNKNOWN_VERSION"
            } else {
                $cmp = Compare-Version $jarVersion $MinSafeVersion
                if ($cmp -lt 0) {
                    $isVulnerable = $true
                    $status       = "VULNERABLE"
                } else {
                    $status = "OK"
                }
            }

            $findings.Add([PSCustomObject]@{
                ScanRoot     = $root
                Path         = $jar.FullName
                FileName     = $jar.Name
                Version      = $jarVersion
                VersionSrc   = $versionSrc
                Status       = $status
                IsVulnerable = $isVulnerable
            })
        }
    }

    return ,$findings
}
#endregion

#region Main scriptblock (runs inside each parallel job)
$checkServicesScript = {
    param(
        [string]$ComputerName,
        [string]$GroupName,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$WebTimeoutSec,
        [int]$InformantWarnMs,
        [int]$EventLogCount,
        [int]$PortCheckTimeout,
        [bool]$AutoRestartStopped,
        [string]$Log4jMinSafeVersion,
        [string]$Log4jScanBlockStr
    )

    #region Inline helpers
    function Get-UptimeString {
        param([datetime]$LastBootTime)
        $u = (Get-Date) - $LastBootTime
        return ("{0}d {1}h {2}m (booted: {3})" -f $u.Days, $u.Hours, $u.Minutes,
            $LastBootTime.ToString("yyyy-MM-dd HH:mm:ss"))
    }

    function Get-ServiceUptime {
        param($CimSession, [int]$ProcessId)
        if ($ProcessId -gt 0) {
            $p = Get-CimInstance -CimSession $CimSession -ClassName Win32_Process `
                -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
            if ($p -and $p.CreationDate) {
                $rt = (Get-Date) - $p.CreationDate
                $s  = if ($rt.Days -gt 0)     { "{0}d {1}h {2}m" -f $rt.Days, $rt.Hours, $rt.Minutes }
                      elseif ($rt.Hours -gt 0) { "{0}h {1}m"      -f $rt.Hours, $rt.Minutes }
                      else                      { "{0}m {1}s"      -f $rt.Minutes, $rt.Seconds }
                return ($s + " (started: " + $p.CreationDate.ToString("yyyy-MM-dd HH:mm:ss") + ")")
            }
        }
        return "N/A"
    }

    function Get-ProcessMemoryMB {
        param($CimSession, [int]$ProcessId)
        if ($ProcessId -gt 0) {
            $p = Get-CimInstance -CimSession $CimSession -ClassName Win32_Process `
                -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
            if ($p) { return [math]::Round($p.WorkingSetSize / 1MB, 1) }
        }
        return $null
    }

    function Get-OrSet-RestartConfig {
        param([string]$ServiceName, [string]$ScHost)
        $info  = sc.exe "\\$ScHost" qfailure $ServiceName 2>&1
        $count = ($info | Select-String "RESTART" | Measure-Object).Count
        if ($count -ne 3) {
            $priorState = if ($count -eq 0) { "Not configured" } else { "$count restart action(s) configured" }
            $fix        = sc.exe "\\$ScHost" failure $ServiceName reset= 86400 `
                              actions= restart/60000/restart/60000/restart/60000 2>&1
            if ($LASTEXITCODE -eq 0) {
                $verify     = sc.exe "\\$ScHost" qfailure $ServiceName 2>&1
                $finalCount = ($verify | Select-String "RESTART" | Measure-Object).Count
                return [PSCustomObject]@{
                    LogNote = "Restart config updated on $ServiceName - was: $priorState"
                    Display = "$finalCount restart action(s) configured [OK]"
                }
            } else {
                return [PSCustomObject]@{
                    LogNote = "Failed to update restart config on $ServiceName - was: $priorState - error: $fix"
                    Display = "$priorState [ERROR - update failed]"
                }
            }
        }
        return [PSCustomObject]@{ LogNote = $null; Display = "3 restart action(s) configured [OK]" }
    }

    function Get-ServiceRestartCount {
        param([string]$ServiceName, [string]$Computer)
        try {
            $evts = Get-WinEvent -ComputerName $Computer -FilterHashtable @{
                LogName   = "System"
                Id        = 7034
                StartTime = (Get-Date).AddDays(-1)
            } -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*$ServiceName*" }
            if ($evts) { return $evts.Count } else { return 0 }
        } catch { return "N/A" }
    }

    function Get-CpuPercent {
        param($CimSession)
        try {
            $cpu = Get-CimInstance -CimSession $CimSession `
                -ClassName Win32_PerfFormattedData_PerfOS_Processor `
                -Filter "Name='_Total'" -ErrorAction Stop
            return [math]::Round($cpu.PercentProcessorTime, 1)
        } catch {
            $p = Get-CimInstance -CimSession $CimSession -ClassName Win32_Processor `
                -ErrorAction SilentlyContinue
            return [math]::Round(($p | Measure-Object -Property LoadPercentage -Average).Average, 1)
        }
    }

    function Get-VisualBar {
        param([double]$Pct, [int]$W = 20)
        $f = [math]::Round($Pct / (100 / $W))
        return ("[" + ("#" * $f).PadRight($W, "-") + "]")
    }

    function Get-ThresholdTag {
        param([double]$Pct)
        if ($Pct -ge 90) { return " [CRITICAL]" }
        elseif ($Pct -ge 75) { return " [WARN]" }
        else { return "" }
    }

    function Invoke-AutoRestart {
        param([string]$ServiceName, [string]$Computer, $CimSession, [bool]$Enabled)
        if (-not $Enabled) { return $null }
        try {
            $svc = Get-CimInstance -CimSession $CimSession -ClassName Win32_Service `
                -Filter "Name='$ServiceName'" -ErrorAction Stop
            if ($svc.State -ne "Running") {
                Invoke-CimMethod -CimSession $CimSession -ClassName Win32_Service `
                    -MethodName StartService -Filter "Name='$ServiceName'" -ErrorAction Stop | Out-Null
                $deadline = (Get-Date).AddSeconds(30)
                while ((Get-Date) -lt $deadline) {
                    Start-Sleep -Milliseconds 500
                    $svc = Get-CimInstance -CimSession $CimSession -ClassName Win32_Service `
                        -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
                    if ($svc.State -eq "Running") { break }
                }
                return "Auto-restart attempted: now $($svc.State)"
            }
        } catch { return "Auto-restart FAILED: $_" }
        return $null
    }

    function Invoke-InformantChecks {
        param([string]$BaseUrl, [string[]]$Components, [int]$TimeoutSec, [int]$WarnMs)
        $jobs = @{}
        foreach ($comp in $Components) {
            $uri = "$BaseUrl&component=$comp"
            $jobs[$comp] = Start-Job -ScriptBlock {
                param($u, $t)
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec $t -ErrorAction Stop
                    $sw.Stop()
                    [PSCustomObject]@{ Content = $r.Content.Trim(); Ms = $sw.ElapsedMilliseconds; Error = $null }
                } catch {
                    $sw.Stop()
                    [PSCustomObject]@{ Content = $null; Ms = $sw.ElapsedMilliseconds; Error = $_.Exception.Message }
                }
            } -ArgumentList $uri, $TimeoutSec
        }
        $results = @{}
        foreach ($comp in $jobs.Keys) {
            $j = $jobs[$comp] | Wait-Job -Timeout ($TimeoutSec + 5)
            if ($j) {
                $results[$comp] = Receive-Job -Job $jobs[$comp]
                Remove-Job -Job $jobs[$comp] -Force
            } else {
                Stop-Job  $jobs[$comp]
                Remove-Job $jobs[$comp] -Force
                $results[$comp] = [PSCustomObject]@{
                    Content = $null; Ms = ($TimeoutSec * 1000); Error = "Timed out"
                }
            }
        }
        return $results
    }
    #endregion

    $instanceResults = New-Object "System.Collections.Generic.List[PSCustomObject]"
    $jobLog          = New-Object System.Collections.Generic.List[string]
    $scHost          = $ComputerName -replace "\..*", ""

    # ── Ping ──────────────────────────────────────────────────────────────────
    $pingOk = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (-not $pingOk) {
        $out = New-Object System.Collections.Generic.List[string]
        $out.Add(""); $out.Add("========================================")
        $out.Add("Zone     : $GroupName"); $out.Add("Server   : $ComputerName")
        $out.Add("  ERROR: Host unreachable (no ping response) - skipping.")
        $out.Add("========================================")
        $instanceResults.Add([PSCustomObject]@{
            ComputerName = $ComputerName; GroupName = $GroupName
            InstanceLabel = "N/A"; Output = $out; CsvRows = $null
            OverallStatus = "DOWN"; TomcatVersion = $null
            EventLines = @(); DriveErrors = @(); DriveWarnings = @()
            InformantResults = @{}; GcCollector = "N/A"; GcWarnings = @()
            GcRecommend = @(); MemPct = 0; CpuAvg = 0; MemUsedGB = 0
            MemTotalGB = 0; MemFreeGB = 0; DrivesSummary = ""; Uptime = "N/A"
            Log4jFindings = @(); JobLog = $jobLog
        })
        return $instanceResults
    }

    # ── CIM session ───────────────────────────────────────────────────────────
    $cimParams = @{ ComputerName = $ComputerName; ErrorAction = "Stop" }
    if ($Credential) { $cimParams["Credential"] = $Credential }
    try { $session = New-CimSession @cimParams }
    catch {
        $out = New-Object System.Collections.Generic.List[string]
        $out.Add(""); $out.Add("========================================")
        $out.Add("Zone     : $GroupName"); $out.Add("Server   : $ComputerName")
        $out.Add("  ERROR: Could not open CIM session - $_")
        $out.Add("========================================")
        $instanceResults.Add([PSCustomObject]@{
            ComputerName = $ComputerName; GroupName = $GroupName
            InstanceLabel = "N/A"; Output = $out; CsvRows = $null
            OverallStatus = "DOWN"; TomcatVersion = $null
            EventLines = @(); DriveErrors = @(); DriveWarnings = @()
            InformantResults = @{}; GcCollector = "N/A"; GcWarnings = @()
            GcRecommend = @(); MemPct = 0; CpuAvg = 0; MemUsedGB = 0
            MemTotalGB = 0; MemFreeGB = 0; DrivesSummary = ""; Uptime = "N/A"
            Log4jFindings = @(); JobLog = $jobLog
        })
        return $instanceResults
    }

    # ── System data ───────────────────────────────────────────────────────────
    $os         = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -ErrorAction Stop
    $allCimSvcs = Get-CimInstance -CimSession $session -ClassName Win32_Service          -ErrorAction Stop
    $allDisks   = Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk `
                      -Filter "DriveType=3" -ErrorAction SilentlyContinue | Sort-Object DeviceID
    $cpuAvg     = Get-CpuPercent -CimSession $session

    $totalMemGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeMemGB  = [math]::Round($os.FreePhysicalMemory      / 1MB, 2)
    $usedMemGB  = [math]::Round($totalMemGB - $freeMemGB, 2)
    $memPct     = if ($totalMemGB -gt 0) { [math]::Round(($usedMemGB / $totalMemGB) * 100, 1) } else { 0 }
    $memBar     = Get-VisualBar -Pct $memPct
    $memTag     = Get-ThresholdTag -Pct $memPct
    $uptimeStr  = Get-UptimeString -LastBootTime $os.LastBootUpTime
    $recentTag  = if (((Get-Date) - $os.LastBootUpTime).TotalHours -lt 24) { "  [WARN - Recent Reboot]" } else { "" }

    $driveErrors   = New-Object System.Collections.Generic.List[string]
    $driveWarnings = New-Object System.Collections.Generic.List[string]
    $drivesSummaryForCsv = ($allDisks | ForEach-Object {
        $t = [math]::Round($_.Size / 1GB, 2); $f = [math]::Round($_.FreeSpace / 1GB, 2)
        $u = [math]::Round($t - $f, 2)
        $p = if ($t -gt 0) { [math]::Round(($u / $t) * 100, 1) } else { 0 }
        if    ($p -ge 90) { $driveErrors.Add(  "$($_.DeviceID) $p% used ($u/$t GB)") }
        elseif ($p -ge 75) { $driveWarnings.Add("$($_.DeviceID) $p% used ($u/$t GB)") }
        "$($_.DeviceID) $p% ($u/$t GB)"
    }) -join " | "

    $driveSummary = if ($allDisks) {
        ($allDisks | ForEach-Object {
            $totGB  = [math]::Round($_.Size / 1GB, 2)
            $freeGB = [math]::Round($_.FreeSpace / 1GB, 2)
            $usedGB = [math]::Round($totGB - $freeGB, 2)
            $pct    = if ($totGB -gt 0) { [math]::Round(($usedGB / $totGB) * 100, 1) } else { 0 }
            $bar    = Get-VisualBar -Pct $pct
            $tag    = Get-ThresholdTag -Pct $pct
            $prefix = if ($pct -ge 90) { "[DRIVE_CRITICAL] " } else { "" }
            ($prefix + "    " + $_.DeviceID + "  " + $bar + " " + $pct + "% used  (" +
             $usedGB + " GB / " + $totGB + " GB)  Free: " + $freeGB + " GB" + $tag)
        }) -join "`n"
    } else { "    No fixed drives found." }

    # ── Event log scan ────────────────────────────────────────────────────────
    $eventLines = New-Object System.Collections.Generic.List[string]
    try {
        $recentEvents = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
            LogName   = "Application"; Level = @(1, 2, 3)
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match "Tomcat|catalina|Content Server" } |
        Select-Object -First $EventLogCount
        foreach ($ev in $recentEvents) {
            $lvl = switch ($ev.Level) { 1{"CRITICAL"} 2{"ERROR"} 3{"WARN"} default{"INFO"} }
            $msg = ($ev.Message -split "`n")[0].Trim()
            if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) + "..." }
            $eventLines.Add("[$lvl] $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))  $($ev.ProviderName): $msg")
        }
    } catch { }

    # ── Locate services ───────────────────────────────────────────────────────
    $tomcatSvc = $allCimSvcs | Where-Object {
        $_.DisplayName -like "*Apache*Tomcat*" -or $_.Name -like "*Tomcat*"
    } | Select-Object -First 1

    $csSvcs = @($allCimSvcs | Where-Object {
        $_.Description -like "*Content Server*" -and
        $_.Description -notlike "*Content Server Admin*"
    })

    $csAdmin = $allCimSvcs | Where-Object {
        $_.Description -like "*Content Server Admin*"
    } | Select-Object -First 1

    # ── Tomcat version + JVM config ───────────────────────────────────────────
    $tomcatVersion = "N/A"; $jrePath = "N/A"; $heapInitMB = $null; $heapMaxMB = $null
    $gcCollector   = "N/A"
    $gcWarnings    = New-Object System.Collections.Generic.List[string]
    $gcRecommend   = New-Object System.Collections.Generic.List[string]
    $tomcatHome    = $null

    if ($tomcatSvc) {
        $icParams = @{
            ComputerName = $ComputerName; ErrorAction = "Stop"
            ArgumentList = $tomcatSvc.Name, $tomcatSvc.PathName, $tomcatSvc.ProcessId
            ScriptBlock  = {
                param([string]$SvcName, [string]$ImagePath, [int]$ProcessId)

                $tomcatHome = $null; $tomcatVersion = "Unknown"; $jrePath = "N/A"
                $heapInitMB = $null; $heapMaxMB = $null

                $regPaths = @(
                    "HKLM:\SOFTWARE\Apache Software Foundation\Procrun 2.0\$SvcName\Parameters\Java",
                    "HKLM:\SOFTWARE\WOW6432Node\Apache Software Foundation\Procrun 2.0\$SvcName\Parameters\Java"
                )
                foreach ($reg in $regPaths) {
                    if (-not (Test-Path $reg)) { continue }
                    $regProps = Get-ItemProperty $reg -ErrorAction SilentlyContinue
                    if ($regProps.Classpath -match "^(.+?)\\lib\\") { $tomcatHome = $Matches[1] }
                    $jvmDll = $regProps.Jvm
                    if ($jvmDll -and (Test-Path $jvmDll)) {
                        $candidate = Split-Path (Split-Path (Split-Path $jvmDll -Parent) -Parent) -Parent
                        $jrePath   = if (Test-Path (Join-Path $candidate "bin\java.exe")) { $candidate }
                                     else { Split-Path $jvmDll -Parent }
                    }
                    if ($regProps.Options) {
                        $optFlat = if ($regProps.Options -is [array]) { $regProps.Options -join ' ' }
                                   else { [string]$regProps.Options }
                        if ($optFlat -match '(?:^|\s)-Xms(\d+)([kmgKMG])') {
                            $val = [long]$Matches[1]
                            $heapInitMB = switch ($Matches[2].ToUpper()) {
                                'K'{[math]::Round($val/1KB,0)} 'M'{$val} 'G'{$val*1024}
                            }
                        }
                        if ($optFlat -match '(?:^|\s)-Xmx(\d+)([kmgKMG])') {
                            $val = [long]$Matches[1]
                            $heapMaxMB = switch ($Matches[2].ToUpper()) {
                                'K'{[math]::Round($val/1KB,0)} 'M'{$val} 'G'{$val*1024}
                            }
                        }
                    }
                    break
                }

                if (-not $tomcatHome) {
                    $cat = [System.Environment]::GetEnvironmentVariable("CATALINA_HOME","Machine")
                    if ($cat -and (Test-Path $cat)) { $tomcatHome = $cat }
                }
                if (-not $tomcatHome -and
                    $ImagePath -match ("^" + [char]34 + "?([^" + [char]34 + "]+\.exe)" + [char]34 + "?")) {
                    $exeDir = Split-Path $Matches[1] -Parent
                    foreach ($c in @((Split-Path $exeDir -Parent), $exeDir)) {
                        if (Test-Path (Join-Path $c "lib")) { $tomcatHome = $c; break }
                    }
                }
                if ($jrePath -eq "N/A") {
                    $jh = [System.Environment]::GetEnvironmentVariable("JAVA_HOME","Machine")
                    if ($jh -and (Test-Path $jh)) { $jrePath = $jh }
                }

                if ($tomcatHome) {
                    foreach ($f in @("RELEASE-NOTES","RUNNING.txt")) {
                        $fp = Join-Path $tomcatHome $f
                        if (Test-Path $fp) {
                            foreach ($ln in (Get-Content $fp -TotalCount 15 -ErrorAction SilentlyContinue)) {
                                if ($ln -match "Apache Tomcat[/ ]([0-9]+\.[0-9]+\.[0-9]+)") {
                                    $tomcatVersion = $Matches[1].Trim(); break
                                }
                            }
                            if ($tomcatVersion -ne "Unknown") { break }
                        }
                    }
                    if ($tomcatVersion -eq "Unknown") {
                        $jarPath = Join-Path $tomcatHome "lib\catalina.jar"
                        if (Test-Path $jarPath) {
                            try {
                                Add-Type -AssemblyName System.IO.Compression.FileSystem
                                $z     = [System.IO.Compression.ZipFile]::OpenRead($jarPath)
                                $entry = $z.Entries | Where-Object { $_.FullName -eq "META-INF/MANIFEST.MF" }
                                if ($entry) {
                                    $rdr = New-Object System.IO.StreamReader($entry.Open())
                                    $content = $rdr.ReadToEnd(); $rdr.Close()
                                    if ($content -match "Implementation-Version:\s*([0-9]+\.[0-9]+\.[0-9]+)") {
                                        $tomcatVersion = $Matches[1].Trim()
                                    }
                                }
                                $z.Dispose()
                            } catch { }
                        }
                    }
                }

                $gcCollector = "Unknown"; $gcFlags = @{}
                $gcWarnings  = New-Object System.Collections.Generic.List[string]
                $gcRecommend = New-Object System.Collections.Generic.List[string]
                $flagLines   = @(); $jcmdPath = $null

                if ($jrePath -and $jrePath -ne "N/A") {
                    $c = Join-Path $jrePath "bin\jcmd.exe"
                    if (Test-Path $c) { $jcmdPath = $c }
                }
                if ($jcmdPath -and $ProcessId -gt 0) {
                    try {
                        $flagLines = & $jcmdPath $ProcessId VM.flags 2>$null
                        foreach ($fl in $flagLines) {
                            if ($fl -match '-XX:([+\-]?)(\w+)(?:=(.+))?') {
                                $gcFlags[$Matches[2]] = if ($Matches[3]) { $Matches[3] } else { $Matches[1] -ne '-' }
                            }
                        }
                        $gcCollector = switch ($true) {
                            { $gcFlags["UseZGC"]             -eq $true } { "ZGC";        break }
                            { $gcFlags["UseShenandoahGC"]    -eq $true } { "Shenandoah"; break }
                            { $gcFlags["UseG1GC"]            -eq $true } { "G1GC";       break }
                            { $gcFlags["UseConcMarkSweepGC"] -eq $true } { "CMS";        break }
                            { $gcFlags["UseParallelGC"]      -eq $true } { "ParallelGC"; break }
                            { $gcFlags["UseSerialGC"]        -eq $true } { "SerialGC";   break }
                            default { "G1GC (default)" }
                        }
                    } catch { $gcCollector = "jcmd error: $_" }
                } elseif (-not $jcmdPath)    { $gcCollector = "jcmd not found (JRE-only install?)" }
                elseif ($ProcessId -le 0)    { $gcCollector = "N/A (service not running)" }

                $totalRamMB = $null
                try {
                    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
                    if ($cs) { $totalRamMB = [math]::Round($cs.TotalPhysicalMemory / 1MB, 0) }
                } catch { }

                if ($gcCollector -in @("CMS","SerialGC","ParallelGC")) {
                    $gcWarnings.Add("Active GC collector is $gcCollector -- not recommended for Content Server")
                    $gcRecommend.Add("Switch to G1GC: add -XX:+UseG1GC and remove -XX:+Use$gcCollector")
                }
                if ($gcCollector -in @("G1GC","G1GC (default)")) {
                    if (-not $gcFlags.ContainsKey("MaxGCPauseMillis")) {
                        $gcRecommend.Add("Set -XX:MaxGCPauseMillis=200 (G1GC pause target; default is 250ms)")
                    }
                    $regionSize = $gcFlags["G1HeapRegionSize"]
                    if (-not $regionSize -or [int]$regionSize -lt 8388608) {
                        $gcRecommend.Add("Set -XX:G1HeapRegionSize=16m (Content Server creates large objects)")
                    }
                    $ihop = $gcFlags["InitiatingHeapOccupancyPercent"]
                    if (-not $ihop -or [int]$ihop -gt 45) {
                        $gcRecommend.Add("Set -XX:InitiatingHeapOccupancyPercent=35 (triggers concurrent marking earlier)")
                    }
                }
                if ($heapInitMB -and $heapMaxMB -and $heapInitMB -ne $heapMaxMB) {
                    $gcWarnings.Add("Xms ($heapInitMB MB) != Xmx ($heapMaxMB MB) -- JVM will resize heap at runtime")
                    $gcRecommend.Add("Set Xms = Xmx to pre-allocate the full heap and avoid resize pauses")
                }
                if ($heapMaxMB -and $totalRamMB) {
                    $heapPct = [math]::Round(($heapMaxMB / $totalRamMB) * 100, 0)
                    if ($heapPct -gt 55) {
                        $gcWarnings.Add("Xmx ($heapMaxMB MB) is $heapPct% of total RAM ($totalRamMB MB)")
                        $gcRecommend.Add("Consider reducing Xmx to ~$([math]::Round($totalRamMB*0.45,0)) MB (~45% of RAM)")
                    } elseif ($heapMaxMB -lt 1024) {
                        $gcWarnings.Add("Xmx is only $heapMaxMB MB -- likely undersized for Content Server")
                        $gcRecommend.Add("Increase Xmx to at least 2048 MB for a production Content Server instance")
                    }
                }
                $hasGcLog = $gcFlags.ContainsKey("Xlog") -or ($flagLines | Select-String "Xlog:gc")
                if (-not $hasGcLog) {
                    $gcRecommend.Add("Enable GC logging: -Xlog:gc*:file=C:\logs\gc.log:time,uptime:filecount=5,filesize=20m")
                }
                if ($gcFlags["HeapDumpOnOutOfMemoryError"] -ne $true) {
                    $gcRecommend.Add("Add -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=C:\logs\tomcat-heap.hprof")
                }
                if (-not $gcFlags.ContainsKey("MaxMetaspaceSize")) {
                    $gcRecommend.Add("Set -XX:MaxMetaspaceSize=256m to prevent unbounded metaspace growth")
                }

                return [PSCustomObject]@{
                    Version     = $tomcatVersion; JrePath     = $jrePath
                    HeapInitMB  = $heapInitMB;    HeapMaxMB   = $heapMaxMB
                    GcCollector = $gcCollector;   GcWarnings  = $gcWarnings
                    GcRecommend = $gcRecommend;   TomcatHome  = $tomcatHome
                }
            }
        }
        if ($Credential) { $icParams["Credential"] = $Credential }
        $tomcatInfo    = try { Invoke-Command @icParams } catch { $null }
        $tomcatVersion = if ($tomcatInfo) { $tomcatInfo.Version     } else { "Unable to retrieve" }
        $jrePath       = if ($tomcatInfo) { $tomcatInfo.JrePath     } else { "N/A" }
        $heapInitMB    = if ($tomcatInfo) { $tomcatInfo.HeapInitMB  } else { $null }
        $heapMaxMB     = if ($tomcatInfo) { $tomcatInfo.HeapMaxMB   } else { $null }
        $gcCollector   = if ($tomcatInfo) { $tomcatInfo.GcCollector } else { "N/A" }
        $tomcatHome    = if ($tomcatInfo) { $tomcatInfo.TomcatHome  } else { $null }
        if ($tomcatInfo -and $tomcatInfo.GcWarnings)  { foreach ($w in $tomcatInfo.GcWarnings)  { $gcWarnings.Add($w)  } }
        if ($tomcatInfo -and $tomcatInfo.GcRecommend) { foreach ($r in $tomcatInfo.GcRecommend) { $gcRecommend.Add($r) } }
    }

    # ── JVM working set + heap display ────────────────────────────────────────
    $wsMB = $null; $jvmHeapText = "N/A"; $jvmHeapCsvStr = "N/A"
    if ($tomcatSvc -and $tomcatSvc.State -eq "Running") {
        $wsMB = Get-ProcessMemoryMB -CimSession $session -ProcessId $tomcatSvc.ProcessId
        if ($wsMB) { $jvmHeapText = "Working Set: ${wsMB} MB"; $jvmHeapCsvStr = "${wsMB} MB" }
    }
    if ($heapInitMB -or $heapMaxMB) {
        $heapCfg       = "Xms: $(if($heapInitMB){"${heapInitMB} MB"}else{"?"})  Xmx: $(if($heapMaxMB){"${heapMaxMB} MB"}else{"?"})"
        $jvmHeapText   = $jvmHeapText + "  |  $heapCfg"
        $jvmHeapCsvStr = $jvmHeapCsvStr + " | $heapCfg"
    }

    # ── Overall status ────────────────────────────────────────────────────────
    $checkTime     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $csvRows       = New-Object "System.Collections.Generic.List[PSCustomObject]"
    $overallStatus = "OK"
    $allInformant  = [ordered]@{}

    if ($driveErrors.Count  -gt 0) { $overallStatus = "CRITICAL" }
    if ($memPct -ge 90)            { $overallStatus = "CRITICAL" }
    if ($cpuAvg -ge 90)            { if ($overallStatus -ne "CRITICAL") { $overallStatus = "WARN" } }
    if ($memPct -ge 75)            { if ($overallStatus -eq "OK") { $overallStatus = "WARN" } }
    if ($driveWarnings.Count -gt 0){ if ($overallStatus -eq "OK") { $overallStatus = "WARN" } }
    if ($recentTag -ne "")         { if ($overallStatus -eq "OK") { $overallStatus = "WARN" } }

    # ── Console header ────────────────────────────────────────────────────────
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add(""); $out.Add("========================================")
    $out.Add("Zone     : $GroupName"); $out.Add("Server   : $ComputerName")
    $out.Add("  Server Uptime: $uptimeStr$recentTag")
    $out.Add("  Memory       : $memBar $memPct% used  ($usedMemGB GB / $totalMemGB GB)  Free: $freeMemGB GB$memTag")
    $out.Add("  CPU          : $(Get-VisualBar -Pct $cpuAvg) $cpuAvg%$(Get-ThresholdTag -Pct $cpuAvg)")
    $out.Add("  Drives:")
    foreach ($dline in ($driveSummary -split "`n")) { $out.Add($dline) }
    if ($driveErrors.Count   -gt 0) { $out.Add("  [ERROR] Drive critical: " + ($driveErrors   -join "; ")) }
    if ($driveWarnings.Count -gt 0) { $out.Add("  [WARN]  Drive warning: "  + ($driveWarnings -join "; ")) }
    $out.Add("========================================")

    # ── Tomcat ────────────────────────────────────────────────────────────────
    $out.Add(""); $out.Add("Tomcat Service:")
    if ($tomcatSvc) {
        $autoNote = Invoke-AutoRestart -ServiceName $tomcatSvc.Name `
            -Computer $ComputerName -CimSession $session -Enabled $AutoRestartStopped
        if ($autoNote) { $out.Add("  [AUTO-RESTART] $autoNote") }

        $tomcatSvcName = $tomcatSvc.Name
        $tomcatSvc = Get-CimInstance -CimSession $session -ClassName Win32_Service `
            -Filter "Name='$tomcatSvcName'" -ErrorAction SilentlyContinue

        $tState         = if ($tomcatSvc.State -eq "Running") { "[RUNNING]" } else { "[STOPPED]" }
        $tUp            = Get-ServiceUptime -CimSession $session -ProcessId $tomcatSvc.ProcessId
        $tRestartResult = Get-OrSet-RestartConfig -ServiceName $tomcatSvc.Name -ScHost $scHost
        if ($tRestartResult.LogNote) { $jobLog.Add("[LOG] $($tRestartResult.LogNote)") }
        $tRestart      = $tRestartResult.Display
        $tRestartCount = Get-ServiceRestartCount -ServiceName $tomcatSvc.Name -Computer $ComputerName
        if ($tomcatSvc.State -ne "Running") { $overallStatus = "DOWN" }

        $out.Add("  Name:               $($tomcatSvc.Name)")
        $out.Add("  Status:             $tState")
        $out.Add("  Display Name:       $($tomcatSvc.DisplayName)")
        $out.Add("  Version:            $tomcatVersion")
        $out.Add("  JRE Path:           $jrePath")
        $out.Add("  Run As:             $($tomcatSvc.StartName)")
        $out.Add("  Service Uptime:     $tUp")
        $out.Add("  Restart Config:     $tRestart")
        $out.Add("  Auto-Restarts(24h): $tRestartCount")
        $out.Add("  Working Set:        $jvmHeapText")
        $out.Add("  GC Collector:       $gcCollector")
        foreach ($w in $gcWarnings)  { $out.Add("  [WARN] GC: $w") }
        foreach ($r in $gcRecommend) { $out.Add("  [INFO] GC Recommend: $r") }

        $csvRows.Add([PSCustomObject]@{
            DateTime = $checkTime; Zone = $GroupName; Server = $ComputerName
            ServiceType = "Tomcat"; ServiceName = $tomcatSvc.Name
            DisplayName = $tomcatSvc.DisplayName; Description = ""
            Status = $tomcatSvc.State; Version = $tomcatVersion; JrePath = $jrePath
            HeapInitMB = $heapInitMB; HeapMaxMB = $heapMaxMB; GcCollector = $gcCollector
            GcWarnings = ($gcWarnings -join " | "); GcRecommend = ($gcRecommend -join " | ")
            RunAs = $tomcatSvc.StartName; ServiceUptime = $tUp
            RestartConfig = $tRestart; AutoRestarts = $tRestartCount
            WorkingSetMB = $jvmHeapCsvStr; ServerUptime = $uptimeStr
            RecentReboot = ($recentTag -ne ""); CpuPct = $cpuAvg; MemPct = $memPct
            MemUsedGB = $usedMemGB; MemTotalGB = $totalMemGB; MemFreeGB = $freeMemGB
            DrivesSummary = $drivesSummaryForCsv; OverallStatus = $overallStatus
        })
    } else {
        $out.Add("  NOT FOUND")
    }

    # ── Content Server(s) ─────────────────────────────────────────────────────
    $out.Add(""); $out.Add("Content Server Service(s):")
    if ($csSvcs) {
        foreach ($cs in $csSvcs) {
            $autoNote = Invoke-AutoRestart -ServiceName $cs.Name `
                -Computer $ComputerName -CimSession $session -Enabled $AutoRestartStopped
            if ($autoNote) { $out.Add("  [AUTO-RESTART] $autoNote") }

            $csName = $cs.Name
            $cs = Get-CimInstance -CimSession $session -ClassName Win32_Service `
                -Filter "Name='$csName'" -ErrorAction SilentlyContinue

            $csState         = if ($cs.State -eq "Running") { "[RUNNING]" } else { "[STOPPED]" }
            $csUp            = Get-ServiceUptime -CimSession $session -ProcessId $cs.ProcessId
            $csRestartResult = Get-OrSet-RestartConfig -ServiceName $cs.Name -ScHost $scHost
            if ($csRestartResult.LogNote) { $jobLog.Add("[LOG] $($csRestartResult.LogNote)") }
            $csRestart      = $csRestartResult.Display
            $csRestartCount = Get-ServiceRestartCount -ServiceName $cs.Name -Computer $ComputerName
            if ($cs.State -ne "Running") { $overallStatus = "DOWN" }

            $out.Add(""); $out.Add("  Instance:           $($cs.Name)")
            $out.Add("  Status:             $csState")
            $out.Add("  Display Name:       $($cs.DisplayName)")
            $out.Add("  Description:        $($cs.Description)")
            $out.Add("  Run As:             $($cs.StartName)")
            $out.Add("  Service Uptime:     $csUp")
            $out.Add("  Restart Config:     $csRestart")
            $out.Add("  Auto-Restarts(24h): $csRestartCount")

            $csInformant = @{}
            if ($cs.State -eq "Running") {
                $pingBase   = "http://$ComputerName/$($cs.Name)/cs?func=informant.ping"
                $components = @("cs","db","adminservers","search","freespace","memoryspace","cpucheck")
                $out.Add(""); $out.Add("  Informant Health Checks (parallel):")
                $iResults = Invoke-InformantChecks -BaseUrl $pingBase -Components $components `
                    -TimeoutSec $WebTimeoutSec -WarnMs $InformantWarnMs
                foreach ($comp in $components) {
                    $ir      = $iResults[$comp]
                    $msLabel = "[$($ir.Ms)ms]"
                    $slowTag = if ($ir.Ms -ge $InformantWarnMs) { " [SLOW]" } else { "" }
                    if ($ir.Error) {
                        $out.Add("    $comp : [ERROR] - $($ir.Error) $msLabel")
                        if ($overallStatus -eq "OK") { $overallStatus = "WARN" }
                        $csInformant[$comp] = [PSCustomObject]@{
                            Status = "ERROR"; Detail = $ir.Error; Ms = $ir.Ms
                            Slow = ($ir.Ms -ge $InformantWarnMs)
                        }
                    } else {
                        $tag    = if ($ir.Content -match "=\s*success") { "SUCCESS" }
                                  elseif ($ir.Content -match "=\s*failure") { "FAILURE" }
                                  else { "OTHER" }
                        $detail = if ($tag -eq "OTHER") { $ir.Content } else { "" }
                        if ($tag -eq "FAILURE") { $overallStatus = "CRITICAL" }
                        $out.Add("    $comp : [$tag] $msLabel$slowTag")
                        $csInformant[$comp] = [PSCustomObject]@{
                            Status = $tag; Detail = $detail; Ms = $ir.Ms
                            Slow = ($ir.Ms -ge $InformantWarnMs)
                        }
                    }
                }
            } else {
                $out.Add("  [INFO] Skipped Informant checks - service is not running.")
            }

            $allInformant[$cs.Name] = $csInformant

            $csvRows.Add([PSCustomObject]@{
                DateTime = $checkTime; Zone = $GroupName; Server = $ComputerName
                ServiceType = "ContentServer"; ServiceName = $cs.Name
                DisplayName = $cs.DisplayName; Description = $cs.Description
                Status = $cs.State; Version = ""; JrePath = ""
                HeapInitMB = $null; HeapMaxMB = $null; GcCollector = ""
                GcWarnings = ""; GcRecommend = ""; RunAs = $cs.StartName
                ServiceUptime = $csUp; RestartConfig = $csRestart
                AutoRestarts = $csRestartCount; WorkingSetMB = "N/A"
                ServerUptime = $uptimeStr; RecentReboot = ($recentTag -ne "")
                CpuPct = $cpuAvg; MemPct = $memPct; MemUsedGB = $usedMemGB
                MemTotalGB = $totalMemGB; MemFreeGB = $freeMemGB
                DrivesSummary = $drivesSummaryForCsv; OverallStatus = $overallStatus
            })
        }
    } else {
        $out.Add("  NOT FOUND")
    }

    # ── Content Server Admin ──────────────────────────────────────────────────
    $out.Add(""); $out.Add("Content Server Admin Service:")
    if ($csAdmin) {
        $autoNote = Invoke-AutoRestart -ServiceName $csAdmin.Name `
            -Computer $ComputerName -CimSession $session -Enabled $AutoRestartStopped
        if ($autoNote) { $out.Add("  [AUTO-RESTART] $autoNote") }

        $csAdminName = $csAdmin.Name
        $csAdmin = Get-CimInstance -CimSession $session -ClassName Win32_Service `
            -Filter "Name='$csAdminName'" -ErrorAction SilentlyContinue

        $caState         = if ($csAdmin.State -eq "Running") { "[RUNNING]" } else { "[STOPPED]" }
        $caUp            = Get-ServiceUptime -CimSession $session -ProcessId $csAdmin.ProcessId
        $caRestartResult = Get-OrSet-RestartConfig -ServiceName $csAdmin.Name -ScHost $scHost
        if ($caRestartResult.LogNote) { $jobLog.Add("[LOG] $($caRestartResult.LogNote)") }
        $caRestart      = $caRestartResult.Display
        $caRestartCount = Get-ServiceRestartCount -ServiceName $csAdmin.Name -Computer $ComputerName
        if ($csAdmin.State -ne "Running") { $overallStatus = "DOWN" }

        $out.Add("  Name:               $($csAdmin.Name)")
        $out.Add("  Status:             $caState")
        $out.Add("  Display Name:       $($csAdmin.DisplayName)")
        $out.Add("  Description:        $($csAdmin.Description)")
        $out.Add("  Run As:             $($csAdmin.StartName)")
        $out.Add("  Service Uptime:     $caUp")
        $out.Add("  Restart Config:     $caRestart")
        $out.Add("  Auto-Restarts(24h): $caRestartCount")

        $csvRows.Add([PSCustomObject]@{
            DateTime = $checkTime; Zone = $GroupName; Server = $ComputerName
            ServiceType = "ContentServerAdmin"; ServiceName = $csAdmin.Name
            DisplayName = $csAdmin.DisplayName; Description = $csAdmin.Description
            Status = $csAdmin.State; Version = ""; JrePath = ""
            HeapInitMB = $null; HeapMaxMB = $null; GcCollector = ""
            GcWarnings = ""; GcRecommend = ""; RunAs = $csAdmin.StartName
            ServiceUptime = $caUp; RestartConfig = $caRestart
            AutoRestarts = $caRestartCount; WorkingSetMB = "N/A"
            ServerUptime = $uptimeStr; RecentReboot = ($recentTag -ne "")
            CpuPct = $cpuAvg; MemPct = $memPct; MemUsedGB = $usedMemGB
            MemTotalGB = $totalMemGB; MemFreeGB = $freeMemGB
            DrivesSummary = $drivesSummaryForCsv; OverallStatus = $overallStatus
        })
    } else {
        $out.Add("  NOT FOUND")
    }

    # =========================================================================
    # LOG4J SCAN
    # Build scan root list:
    #   1. Tomcat webapps dir  ($tomcatHome\webapps)
    #   2. Each Content Server instance webservices dir
    #      (derived from service PathName: walk up from exe to instance root,
    #       then append \webservices)
    # =========================================================================
    $log4jScanRoots = New-Object System.Collections.Generic.List[string]

    # Tomcat webapps
    if ($tomcatHome) {
        $log4jScanRoots.Add((Join-Path $tomcatHome "webapps"))
    }

    # Content Server webservices — one per CS instance
    foreach ($cs in $csSvcs) {
        if ($cs.PathName) {
            # PathName may be quoted: "C:\path\to\service.exe" args...
            $exePath = ($cs.PathName -replace '^"?([^"]+\.exe).*$','$1').Trim('"')
            # Walk up: exe -> bin (or similar) -> instance root
            $csRoot = Split-Path (Split-Path $exePath -Parent) -Parent
            $wsDir  = Join-Path $csRoot "webservices"
            $log4jScanRoots.Add($wsDir)
        }
    }

    # Run the scan via Invoke-Command so it executes on the remote server.
    # Reconstruct the scriptblock from the serialized string — required for PS 5.1
    # job boundary compatibility (scriptblock objects do not survive serialization).
    $log4jFindings = @()
    if ($log4jScanRoots.Count -gt 0) {
        $scanBlock = [scriptblock]::Create($Log4jScanBlockStr)
        $scanArgs  = @(,[string[]]$log4jScanRoots) + @($Log4jMinSafeVersion)
        try {
            $icLog4jParams = @{
                ComputerName = $ComputerName
                ScriptBlock  = $scanBlock
                ArgumentList = $scanArgs
                ErrorAction  = "Stop"
            }
            if ($Credential) { $icLog4jParams["Credential"] = $Credential }
            $log4jFindings = @(Invoke-Command @icLog4jParams)
        } catch {
            $jobLog.Add("[WARN] Log4j scan failed on $ComputerName : $_")
            $log4jFindings = @([PSCustomObject]@{
                ScanRoot = ""; Path = ""; FileName = ""; Version = "ERROR"
                VersionSrc = ""; Status = "SCAN_ERROR"; IsVulnerable = $false
            })
        }
    }

    # Console output for log4j findings
    $out.Add(""); $out.Add("Log4j Scan  (min safe: $Log4jMinSafeVersion):")
    $hasVulnerable = $false
    foreach ($f in $log4jFindings) {
        switch ($f.Status) {
            "VULNERABLE" {
                $hasVulnerable = $true
                $out.Add("  [VULNERABLE] $($f.FileName)  v$($f.Version) (src: $($f.VersionSrc))")
                $out.Add("               Path: $($f.Path)")
                if ($overallStatus -ne "CRITICAL") { $overallStatus = "WARN" }
            }
            "OK" {
                $out.Add("  [OK]         $($f.FileName)  v$($f.Version) (src: $($f.VersionSrc))")
                $out.Add("               Path: $($f.Path)")
            }
            "NOT_FOUND" {
                $out.Add("  [NOT FOUND]  No log4j jars found under: $($f.ScanRoot)")
            }
            "SCAN_ROOT_NOT_FOUND" {
                $out.Add("  [MISSING]    Scan root does not exist: $($f.Path)")
            }
            "UNKNOWN_VERSION" {
                $out.Add("  [UNKNOWN]    $($f.FileName) — version could not be determined")
                $out.Add("               Path: $($f.Path)")
            }
            "SCAN_ERROR" {
                $out.Add("  [ERROR]      Scan failed — check log for details")
            }
        }
    }
    if ($hasVulnerable) {
        $out.Add("  ** VULNERABLE log4j version(s) found — immediate action required **")
    }

    # ── Event log ─────────────────────────────────────────────────────────────
    if ($eventLines.Count -gt 0) {
        $out.Add(""); $out.Add("Recent Application Log Events (last 24h, Tomcat/CS related):")
        foreach ($line in $eventLines) { $out.Add("  $line") }
        if ($overallStatus -eq "OK") { $overallStatus = "WARN" }
    }

    Remove-CimSession $session -ErrorAction SilentlyContinue

    $instanceResults.Add([PSCustomObject]@{
        ComputerName     = $ComputerName;    GroupName        = $GroupName
        InstanceLabel    = $ComputerName;    Output           = $out
        CsvRows          = $csvRows;         OverallStatus    = $overallStatus
        TomcatVersion    = $tomcatVersion;   EventLines       = $eventLines
        DriveErrors      = $driveErrors;     DriveWarnings    = $driveWarnings
        InformantResults = $allInformant;    GcCollector      = $gcCollector
        GcWarnings       = $gcWarnings;      GcRecommend      = $gcRecommend
        MemPct           = $memPct;          CpuAvg           = $cpuAvg
        MemUsedGB        = $usedMemGB;       MemTotalGB       = $totalMemGB
        MemFreeGB        = $freeMemGB;       DrivesSummary    = $drivesSummaryForCsv
        Uptime           = $uptimeStr;       Log4jFindings    = $log4jFindings
        JobLog           = $jobLog
    })
    return $instanceResults
}
#endregion

#region Main
$Credential = $null

$consoleAvailable = $false
try { $null = [System.Console]::KeyAvailable; $consoleAvailable = $true } catch { }

if ($consoleAvailable) {
    try { while ([System.Console]::KeyAvailable) { [System.Console]::ReadKey($true) | Out-Null } } catch { }
    Write-Host "Use alternate credentials? (y/n)  [auto-skipping in 10 seconds]" -ForegroundColor Cyan
    $useCreds = ""; $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        $keyAvail = $false
        try { $keyAvail = [System.Console]::KeyAvailable } catch { break }
        if ($keyAvail) {
            $key = [System.Console]::ReadKey($true); $useCreds = $key.KeyChar.ToString().ToLower()
            Write-Host $useCreds; break
        }
        Start-Sleep -Milliseconds 100
    }
    if ($useCreds -eq "y") { $Credential = Get-Credential -Message "Enter credentials for remote servers" }
} else {
    Write-Host "Non-interactive session detected - using default credentials." -ForegroundColor Gray
}

$startTime = Get-Date
Write-Log "Remote Service Status Check" -Color Cyan
Write-Log "Started     : $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Gray
Write-Log "Log4j min   : $Log4jMinSafeVersion" -Color Gray
Write-Log "Log file    : $logFile" -Color Gray
Write-Log ""

# ── Start parallel jobs ───────────────────────────────────────────────────────
$jobs = New-Object "System.Collections.Generic.List[hashtable]"
foreach ($group in $serverGroups.Keys) {
    foreach ($server in $serverGroups[$group]) {
        while ((Get-Job -State Running).Count -ge $MaxParallelJobs) { Start-Sleep -Milliseconds 200 }
        $j = Start-Job -ScriptBlock $checkServicesScript `
                 -ArgumentList $server, $group, $Credential, $webTimeoutSec, $InformantWarnMs,
                               $eventLogCount, $portCheckTimeout, ($AutoRestartStopped.IsPresent),
                               $Log4jMinSafeVersion, $log4jScanBlock.ToString()
        $jobs.Add(@{ Job = $j; Server = $server; Group = $group })
        Write-Log "Queued: [$group] $server" -Color Gray
    }
}

Write-Log "Checking $serverCount server(s) in parallel (max $MaxParallelJobs concurrent)..." -Color Yellow

foreach ($entry in $jobs) {
    $finished = $entry.Job | Wait-Job -Timeout $jobTimeoutSec
    if (-not $finished) {
        Write-Log "TIMEOUT: [$($entry.Group)] $($entry.Server) - skipping." -Color Red
        Stop-Job $entry.Job; Remove-Job $entry.Job -Force; $entry.Job = $null
    }
}

$results = @()
foreach ($entry in $jobs) {
    if ($null -ne $entry.Job) {
        $r = Receive-Job -Job $entry.Job -ErrorAction SilentlyContinue
        if ($r) { $results += $r }
        Remove-Job $entry.Job -Force
    }
}

foreach ($result in $results) {
    if ($result.JobLog -and $result.JobLog.Count -gt 0) { Add-Content -Path $logFile -Value $result.JobLog }
}

# ── Delta detection ───────────────────────────────────────────────────────────
$prevData = @{}
$prevCsvs = Get-ChildItem -Path $PSScriptRoot -Filter "ServiceCheck_*.csv" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne (Split-Path $csvFile -Leaf) } |
            Sort-Object LastWriteTime -Descending
if ($prevCsvs) {
    $prevRows = Import-Csv -Path $prevCsvs[0].FullName -ErrorAction SilentlyContinue
    foreach ($row in $prevRows) { $prevData["$($row.Server)|$($row.ServiceName)"] = $row }
    Write-Log "Comparing against previous run: $($prevCsvs[0].Name)" -Color Gray
}

# ── Console output ────────────────────────────────────────────────────────────
$prevGroup   = $null
$zoneSummary = [ordered]@{}
$allVersions = @{}

foreach ($result in ($results | Sort-Object GroupName, ComputerName)) {
    $grp = $result.GroupName
    if (-not $zoneSummary.Contains($grp)) { $zoneSummary[$grp] = @{ OK=0; WARN=0; DOWN=0; CRITICAL=0 } }
    $zoneSummary[$grp][$result.OverallStatus]++

    if ($result.TomcatVersion -and
        $result.TomcatVersion -notin @("N/A","Unknown","Unable to retrieve")) {
        if (-not $allVersions.Contains($grp)) { $allVersions[$grp] = @{} }
        $allVersions[$grp][$result.ComputerName] = $result.TomcatVersion
    }

    if ($grp -ne $prevGroup) {
        Write-Log ""; Write-Log "########################################" -Color Magenta
        Write-Log "# Zone: $grp" -Color Magenta
        Write-Log "########################################" -Color Magenta
        $prevGroup = $grp
    }

    $deltaDetails = New-Object System.Collections.Generic.List[string]
    if ($result.CsvRows) {
        foreach ($row in $result.CsvRows) {
            $key  = "$($row.Server)|$($row.ServiceName)"; $prev = $prevData[$key]
            if ($prev) {
                if ($prev.Status  -ne $row.Status)  { $deltaDetails.Add("$($row.ServiceName): Status $($prev.Status) -> $($row.Status)") }
                if ($prev.Version -and $prev.Version -ne $row.Version) { $deltaDetails.Add("$($row.ServiceName): Version $($prev.Version) -> $($row.Version)") }
            }
        }
    }
    $hasDelta = $deltaDetails.Count -gt 0
    $isClean  = ($result.OverallStatus -eq "OK") -and (-not $hasDelta)
    if ($QuietOK -and $isClean) { Write-Log "  $($result.ComputerName) : OK" -Color Green; continue }

    foreach ($line in $result.Output) {
        $color = "White"
        if     ($line -match "^={3,}|Server   :")                                                         { $color = "Cyan"    }
        elseif ($line -match "Zone     :")                                                                 { $color = "Magenta" }
        elseif ($line -match "Recent Reboot")                                                              { $color = "Yellow"  }
        elseif ($line -match "Tomcat Service:|Content Server Service|Informant Health|Log4j Scan")        { $color = "Yellow"  }
        elseif ($line -match "^\[DRIVE_CRITICAL\] ")                                                      { $color = "Red"     }
        elseif ($line -match "\[RUNNING\]|\[SUCCESS\]|\[OK\]")                                            { $color = "Green"   }
        elseif ($line -match "\[STOPPED\]|ERROR:|NOT FOUND|\[FAILURE\]|\[ERROR\]|\[CRITICAL\]|\[VULNERABLE\]") { $color = "Red" }
        elseif ($line -match "\[WARN\]|\[OTHER\]|\[SLOW\]|\[UNKNOWN\]|\[MISSING\]")                      { $color = "Yellow"  }
        elseif ($line -match "\[AUTO-RESTART\]")                                                          { $color = "Cyan"    }
        elseif ($line -match "Working Set:|Auto-Restarts:|CPU|Memory|Drive")                              { $color = "Cyan"    }
        elseif ($line -match "Run As:|Restart Config:|Service Uptime:")                                   { $color = "Cyan"    }
        elseif ($line -match "Description:|Display Name:")                                                { $color = "Gray"    }
        Write-Log $line -Color $color
    }
    if ($hasDelta) {
        Write-Log "  >> Changes detected on $($result.ComputerName):" -Color Yellow
        foreach ($d in $deltaDetails) { Write-Log "     $d" -Color Yellow }
    }
}

# ── Zone rollup ───────────────────────────────────────────────────────────────
Write-Log ""; Write-Log "======== Zone Rollup ========" -Color Cyan
foreach ($grp in $zoneSummary.Keys) {
    $s   = $zoneSummary[$grp]
    $tot = $s.OK + $s.WARN + $s.DOWN + $s.CRITICAL
    $col = if ($s.DOWN -gt 0 -or $s.CRITICAL -gt 0) { "Red" } elseif ($s.WARN -gt 0) { "Yellow" } else { "Green" }
    Write-Log ("  {0,-40} : {1} OK, {2} WARN, {3} CRITICAL, {4} DOWN  (of {5})" -f `
        $grp, $s.OK, $s.WARN, $s.CRITICAL, $s.DOWN, $tot) -Color $col

    if ($allVersions.Contains($grp) -and $allVersions[$grp].Count -gt 1) {
        $vg       = $allVersions[$grp].Values | Group-Object | Sort-Object Count -Descending
        $majority = $vg[0].Name
        $outliers = $allVersions[$grp].GetEnumerator() | Where-Object { $_.Value -ne $majority }
        if ($outliers) {
            Write-Log "    [VERSION MISMATCH] Majority: $majority - outliers:" -Color Yellow
            foreach ($o in $outliers) { Write-Log "      $($o.Key) : $($o.Value)" -Color Yellow }
        }
    }
}
Write-Log "=============================" -Color Cyan

# ── Log4j rollup across all servers ──────────────────────────────────────────
$allLog4j = $results | ForEach-Object { $_.Log4jFindings } | Where-Object { $_ }
$vulnLog4j = @($allLog4j | Where-Object { $_.IsVulnerable })
if ($vulnLog4j.Count -gt 0) {
    Write-Log "" ; Write-Log "======== Log4j Vulnerable Findings ========" -Color Red
    foreach ($f in $vulnLog4j) {
        Write-Log "  [VULNERABLE] $($f.FileName)  v$($f.Version)  Path: $($f.Path)" -Color Red
    }
    Write-Log "  Total vulnerable jar(s): $($vulnLog4j.Count)" -Color Red
    Write-Log "===========================================" -Color Red
}

# ── CSV ───────────────────────────────────────────────────────────────────────
$allCsvRows = $results | ForEach-Object { $_.CsvRows } | Where-Object { $_ }
if ($allCsvRows) {
    $allCsvRows | Sort-Object Zone, Server, ServiceType |
        Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Log "CSV saved to   : $csvFile" -Color Green
} else {
    Write-Log "No CSV data to export." -Color Yellow
}

# ── Log4j CSV (separate file for easy distribution to security team) ──────────
$log4jCsvFile = Join-Path $PSScriptRoot ("Log4jScan_" + $timestamp + ".csv")
if ($allLog4j) {
    # Attach ComputerName to each finding for the CSV
    $log4jCsvRows = foreach ($result in $results) {
        foreach ($f in $result.Log4jFindings) {
            [PSCustomObject]@{
                DateTime     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                Server       = $result.ComputerName
                Zone         = $result.GroupName
                Status       = $f.Status
                IsVulnerable = $f.IsVulnerable
                Version      = $f.Version
                VersionSrc   = $f.VersionSrc
                FileName     = $f.FileName
                Path         = $f.Path
                ScanRoot     = $f.ScanRoot
                MinSafeVer   = $Log4jMinSafeVersion
            }
        }
    }
    $log4jCsvRows | Sort-Object IsVulnerable -Descending |
        Export-Csv -Path $log4jCsvFile -NoTypeInformation -Encoding UTF8
    Write-Log "Log4j CSV      : $log4jCsvFile" -Color Green
}

# ── Alerts ────────────────────────────────────────────────────────────────────
$issueRows = $allCsvRows | Where-Object { $_.OverallStatus -in @("DOWN","CRITICAL") }
$alertLines = @()
if ($issueRows) {
    $alertLines += "Service Check Alert - $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))", ""
    foreach ($r in $issueRows) {
        $alertLines += "[$($r.OverallStatus)] $($r.Zone) / $($r.Server) - $($r.ServiceType) ($($r.ServiceName)): $($r.Status)"
    }
}
if ($vulnLog4j.Count -gt 0) {
    $alertLines += "", "=== Log4j VULNERABLE ==="
    foreach ($f in $vulnLog4j) { $alertLines += "  $($f.FileName) v$($f.Version) on -- Path: $($f.Path)" }
}
if ($alertLines.Count -gt 0) {
    $bodyText = $alertLines -join "`n"
    try {
        Send-MailMessage -SmtpServer $SmtpServer -From $EmailFrom -To $EmailTo `
            -Subject "Service/Log4j Alert: $($issueRows.Count) service issue(s), $($vulnLog4j.Count) vulnerable log4j jar(s)" `
            -Body $bodyText -ErrorAction Stop
        Write-Log "Alert email sent to $EmailTo" -Color Green
    } catch { Write-Log "Failed to send alert email: $_" -Color Red }
    if ($TeamsWebhookUrl) {
        Send-TeamsAlert -WebhookUrl $TeamsWebhookUrl `
            -Title "Alert: $($issueRows.Count) service issue(s), $($vulnLog4j.Count) vulnerable log4j" `
            -Body $bodyText
        Write-Log "Teams alert sent." -Color Green
    }
}

# ── Footer ────────────────────────────────────────────────────────────────────
$endTime = Get-Date; $dur = $endTime - $startTime
Write-Log ""; Write-Log "========================================" -Color Cyan
Write-Log "Completed : $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Cyan
Write-Log "Duration  : $($dur.ToString('mm\:ss'))" -Color Cyan
Write-Log "========================================" -Color Cyan
Write-Log "Log      : $logFile"        -Color Green
Write-Log "CSV      : $csvFile"        -Color Green
Write-Log "Log4j CSV: $log4jCsvFile"   -Color Green
#endregion

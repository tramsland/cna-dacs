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
# Resolve the directory the script lives in — used for ALL output files.
# Priority: $PSScriptRoot (set by PS when run as a file) -> $MyInvocation.MyCommand.Path
# -> $MyInvocation.ScriptName -> explicit error. Never fall back to cwd so files
# never end up in C:\logs or wherever the shell happens to be open.
$scriptDir = $null
if ($PSScriptRoot -and (Test-Path $PSScriptRoot)) {
    $scriptDir = $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    $scriptDir = Split-Path $MyInvocation.MyCommand.Path -Parent
} elseif ($MyInvocation.ScriptName) {
    $scriptDir = Split-Path $MyInvocation.ScriptName -Parent
}
if (-not $scriptDir) {
    Write-Host "ERROR: Cannot determine script directory. Run the script as a file: .\status.ps1" -ForegroundColor Red
    Write-Host "Do not paste or dot-source this script -- save it to disk and run it directly." -ForegroundColor Yellow
    exit 1
}
$scriptDir = $scriptDir.TrimEnd('\').TrimEnd('/')

$configFile = Join-Path $scriptDir "servers.txt"
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
$logFile          = Join-Path $scriptDir ("ServiceCheck_" + $timestamp + ".log")
$csvFile          = Join-Path $scriptDir ("ServiceCheck_" + $timestamp + ".csv")
$htmlFile         = Join-Path $scriptDir ("ServiceCheck_" + $timestamp + ".html")
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
            [void]$findings.Add([PSCustomObject]@{
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
            [void]$findings.Add([PSCustomObject]@{
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

            [void]$findings.Add([PSCustomObject]@{
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
        [void]$out.Add(""); [void]$out.Add("========================================")
        [void]$out.Add("Zone     : $GroupName"); [void]$out.Add("Server   : $ComputerName")
        [void]$out.Add("  ERROR: Host unreachable (no ping response) - skipping.")
        [void]$out.Add("========================================")
        [void]$instanceResults.Add([PSCustomObject]@{
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

    # ── CIM session (WSMan first, DCOM fallback) ──────────────────────────────
    # WSMan (WinRM) is preferred; fall back to DCOM if WinRM is unavailable.
    $session = $null
    $sessionError = $null
    $sessionProtocol = $null
    foreach ($protocol in @('Wsman','Dcom')) {
        try {
            $opt = New-CimSessionOption -Protocol $protocol
            $cimParams = @{ ComputerName = $ComputerName; SessionOption = $opt; ErrorAction = 'Stop' }
            if ($Credential) { $cimParams['Credential'] = $Credential }
            $session = New-CimSession @cimParams
            [void]$jobLog.Add("[INFO] $ComputerName: CIM session established via $protocol")
            $sessionProtocol = $protocol
            break
        } catch {
            $sessionError = $_
            [void]$jobLog.Add("[WARN] $ComputerName: CIM/$protocol failed - $_")
        }
    }
    if (-not $session) {
        $out = New-Object System.Collections.Generic.List[string]
        [void]$out.Add(""); [void]$out.Add("========================================")
        [void]$out.Add("Zone     : $GroupName"); [void]$out.Add("Server   : $ComputerName")
        [void]$out.Add("  ERROR: Could not open CIM session (tried WSMan and DCOM) - $sessionError")
        [void]$out.Add("========================================")
        [void]$instanceResults.Add([PSCustomObject]@{
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
        if    ($p -ge 90) { [void]$driveErrors.Add(  "$($_.DeviceID) $p% used ($u/$t GB)") }
        elseif ($p -ge 75) { [void]$driveWarnings.Add("$($_.DeviceID) $p% used ($u/$t GB)") }
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
            [void]$eventLines.Add("[$lvl] $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))  $($ev.ProviderName): $msg")
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
                    [void]$gcWarnings.Add("Active GC collector is $gcCollector -- not recommended for Content Server")
                    [void]$gcRecommend.Add("Switch to G1GC: add -XX:+UseG1GC and remove -XX:+Use$gcCollector")
                }
                if ($gcCollector -in @("G1GC","G1GC (default)")) {
                    if (-not $gcFlags.ContainsKey("MaxGCPauseMillis")) {
                        [void]$gcRecommend.Add("Set -XX:MaxGCPauseMillis=200 (G1GC pause target; default is 250ms)")
                    }
                    $regionSize = $gcFlags["G1HeapRegionSize"]
                    if (-not $regionSize -or [int]$regionSize -lt 8388608) {
                        [void]$gcRecommend.Add("Set -XX:G1HeapRegionSize=16m (Content Server creates large objects)")
                    }
                    $ihop = $gcFlags["InitiatingHeapOccupancyPercent"]
                    if (-not $ihop -or [int]$ihop -gt 45) {
                        [void]$gcRecommend.Add("Set -XX:InitiatingHeapOccupancyPercent=35 (triggers concurrent marking earlier)")
                    }
                }
                if ($heapInitMB -and $heapMaxMB -and $heapInitMB -ne $heapMaxMB) {
                    [void]$gcWarnings.Add("Xms ($heapInitMB MB) != Xmx ($heapMaxMB MB) -- JVM will resize heap at runtime")
                    [void]$gcRecommend.Add("Set Xms = Xmx to pre-allocate the full heap and avoid resize pauses")
                }
                if ($heapMaxMB -and $totalRamMB) {
                    $heapPct = [math]::Round(($heapMaxMB / $totalRamMB) * 100, 0)
                    if ($heapPct -gt 55) {
                        [void]$gcWarnings.Add("Xmx ($heapMaxMB MB) is $heapPct% of total RAM ($totalRamMB MB)")
                        [void]$gcRecommend.Add("Consider reducing Xmx to ~$([math]::Round($totalRamMB*0.45,0)) MB (~45% of RAM)")
                    } elseif ($heapMaxMB -lt 1024) {
                        [void]$gcWarnings.Add("Xmx is only $heapMaxMB MB -- likely undersized for Content Server")
                        [void]$gcRecommend.Add("Increase Xmx to at least 2048 MB for a production Content Server instance")
                    }
                }
                $hasGcLog = $gcFlags.ContainsKey("Xlog") -or ($flagLines | Select-String "Xlog:gc")
                if (-not $hasGcLog) {
                    [void]$gcRecommend.Add("Enable GC logging: -Xlog:gc*:file=C:\logs\gc.log:time,uptime:filecount=5,filesize=20m")
                }
                if ($gcFlags["HeapDumpOnOutOfMemoryError"] -ne $true) {
                    [void]$gcRecommend.Add("Add -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=C:\logs\tomcat-heap.hprof")
                }
                if (-not $gcFlags.ContainsKey("MaxMetaspaceSize")) {
                    [void]$gcRecommend.Add("Set -XX:MaxMetaspaceSize=256m to prevent unbounded metaspace growth")
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
        # Invoke-Command requires WinRM; skip gracefully if we fell back to DCOM.
        $tomcatInfo = $null
        $icError    = $null
        try   { $tomcatInfo = Invoke-Command @icParams }
        catch { $icError = $_; [void]$jobLog.Add("[WARN] $ComputerName: Invoke-Command (Tomcat info) failed - $_") }
        $tomcatVersion = if ($tomcatInfo) { $tomcatInfo.Version     } elseif ($icError) { "WinRM unavailable" } else { "Unable to retrieve" }
        $jrePath       = if ($tomcatInfo) { $tomcatInfo.JrePath     } else { "N/A" }
        $heapInitMB    = if ($tomcatInfo) { $tomcatInfo.HeapInitMB  } else { $null }
        $heapMaxMB     = if ($tomcatInfo) { $tomcatInfo.HeapMaxMB   } else { $null }
        $gcCollector   = if ($tomcatInfo) { $tomcatInfo.GcCollector } elseif ($icError) { "N/A (WinRM unavailable)" } else { "N/A" }
        $tomcatHome    = if ($tomcatInfo) { $tomcatInfo.TomcatHome  } else { $null }
        if ($tomcatInfo -and $tomcatInfo.GcWarnings)  { foreach ($w in $tomcatInfo.GcWarnings)  { [void]$gcWarnings.Add($w)  } }
        if ($tomcatInfo -and $tomcatInfo.GcRecommend) { foreach ($r in $tomcatInfo.GcRecommend) { [void]$gcRecommend.Add($r) } }
    }

    # ── JVM working set + heap display ────────────────────────────────────────
    $wsMB = $null; $jvmHeapText = "N/A"; $jvmHeapCsvStr = "N/A"
    if ($tomcatSvc -and $tomcatSvc.State -eq "Running") {
        $wsMB = Get-ProcessMemoryMB -CimSession $session -ProcessId $tomcatSvc.ProcessId
        if ($wsMB) { $jvmHeapText = "Working Set: ${wsMB} MB"; $jvmHeapCsvStr = "${wsMB} MB" }
    }
    if ($heapInitMB -or $heapMaxMB) {
        $heapInitStr   = if ($heapInitMB) { "${heapInitMB} MB" } else { '?' }
        $heapMaxStr    = if ($heapMaxMB)  { "${heapMaxMB} MB" }  else { '?' }
        $heapCfg       = "Xms: $heapInitStr  Xmx: $heapMaxStr"
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
    [void]$out.Add(""); [void]$out.Add("========================================")
    [void]$out.Add("Zone     : $GroupName"); [void]$out.Add("Server   : $ComputerName")
    [void]$out.Add("  Server Uptime: $uptimeStr$recentTag")
    [void]$out.Add("  Memory       : $memBar $memPct% used  ($usedMemGB GB / $totalMemGB GB)  Free: $freeMemGB GB$memTag")
    [void]$out.Add("  CPU          : $(Get-VisualBar -Pct $cpuAvg) $cpuAvg%$(Get-ThresholdTag -Pct $cpuAvg)")
    [void]$out.Add("  Drives:")
    foreach ($dline in ($driveSummary -split "`n")) { [void]$out.Add($dline) }
    if ($driveErrors.Count   -gt 0) { [void]$out.Add("  [ERROR] Drive critical: " + ($driveErrors   -join "; ")) }
    if ($driveWarnings.Count -gt 0) { [void]$out.Add("  [WARN]  Drive warning: "  + ($driveWarnings -join "; ")) }
    [void]$out.Add("========================================")

    # ── Tomcat ────────────────────────────────────────────────────────────────
    [void]$out.Add(""); [void]$out.Add("Tomcat Service:")
    if ($tomcatSvc) {
        $autoNote = Invoke-AutoRestart -ServiceName $tomcatSvc.Name `
            -Computer $ComputerName -CimSession $session -Enabled $AutoRestartStopped
        if ($autoNote) { [void]$out.Add("  [AUTO-RESTART] $autoNote") }

        $tomcatSvcName = $tomcatSvc.Name
        $tomcatSvc = Get-CimInstance -CimSession $session -ClassName Win32_Service `
            -Filter "Name='$tomcatSvcName'" -ErrorAction SilentlyContinue

        $tState         = if ($tomcatSvc.State -eq "Running") { "[RUNNING]" } else { "[STOPPED]" }
        $tUp            = Get-ServiceUptime -CimSession $session -ProcessId $tomcatSvc.ProcessId
        $tRestartResult = Get-OrSet-RestartConfig -ServiceName $tomcatSvc.Name -ScHost $scHost
        if ($tRestartResult.LogNote) { [void]$jobLog.Add("[LOG] $($tRestartResult.LogNote)") }
        $tRestart      = $tRestartResult.Display
        $tRestartCount = Get-ServiceRestartCount -ServiceName $tomcatSvc.Name -Computer $ComputerName
        if ($tomcatSvc.State -ne "Running") { $overallStatus = "DOWN" }

        [void]$out.Add("  Name:               $($tomcatSvc.Name)")
        [void]$out.Add("  Status:             $tState")
        [void]$out.Add("  Display Name:       $($tomcatSvc.DisplayName)")
        [void]$out.Add("  Version:            $tomcatVersion")
        [void]$out.Add("  JRE Path:           $jrePath")
        [void]$out.Add("  Run As:             $($tomcatSvc.StartName)")
        [void]$out.Add("  Service Uptime:     $tUp")
        [void]$out.Add("  Restart Config:     $tRestart")
        [void]$out.Add("  Auto-Restarts(24h): $tRestartCount")
        [void]$out.Add("  Working Set:        $jvmHeapText")
        [void]$out.Add("  GC Collector:       $gcCollector")
        foreach ($w in $gcWarnings)  { [void]$out.Add("  [WARN] GC: $w") }
        foreach ($r in $gcRecommend) { [void]$out.Add("  [INFO] GC Recommend: $r") }

        [void]$csvRows.Add([PSCustomObject]@{
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
        [void]$out.Add("  NOT FOUND")
    }

    # ── Content Server(s) ─────────────────────────────────────────────────────
    [void]$out.Add(""); [void]$out.Add("Content Server Service(s):")
    if ($csSvcs) {
        foreach ($cs in $csSvcs) {
            $autoNote = Invoke-AutoRestart -ServiceName $cs.Name `
                -Computer $ComputerName -CimSession $session -Enabled $AutoRestartStopped
            if ($autoNote) { [void]$out.Add("  [AUTO-RESTART] $autoNote") }

            $csName = $cs.Name
            $cs = Get-CimInstance -CimSession $session -ClassName Win32_Service `
                -Filter "Name='$csName'" -ErrorAction SilentlyContinue

            $csState         = if ($cs.State -eq "Running") { "[RUNNING]" } else { "[STOPPED]" }
            $csUp            = Get-ServiceUptime -CimSession $session -ProcessId $cs.ProcessId
            $csRestartResult = Get-OrSet-RestartConfig -ServiceName $cs.Name -ScHost $scHost
            if ($csRestartResult.LogNote) { [void]$jobLog.Add("[LOG] $($csRestartResult.LogNote)") }
            $csRestart      = $csRestartResult.Display
            $csRestartCount = Get-ServiceRestartCount -ServiceName $cs.Name -Computer $ComputerName
            if ($cs.State -ne "Running") { $overallStatus = "DOWN" }

            [void]$out.Add(""); [void]$out.Add("  Instance:           $($cs.Name)")
            [void]$out.Add("  Status:             $csState")
            [void]$out.Add("  Display Name:       $($cs.DisplayName)")
            [void]$out.Add("  Description:        $($cs.Description)")
            [void]$out.Add("  Run As:             $($cs.StartName)")
            [void]$out.Add("  Service Uptime:     $csUp")
            [void]$out.Add("  Restart Config:     $csRestart")
            [void]$out.Add("  Auto-Restarts(24h): $csRestartCount")

            $csInformant = @{}
            if ($cs.State -eq "Running") {
                $pingBase   = "http://$ComputerName/$($cs.Name)/cs?func=informant.ping"
                $components = @("cs","db","adminservers","search","freespace","memoryspace","cpucheck")
                [void]$out.Add(""); [void]$out.Add("  Informant Health Checks (parallel):")
                $iResults = Invoke-InformantChecks -BaseUrl $pingBase -Components $components `
                    -TimeoutSec $WebTimeoutSec -WarnMs $InformantWarnMs
                foreach ($comp in $components) {
                    $ir      = $iResults[$comp]
                    $msLabel = "[$($ir.Ms)ms]"
                    $slowTag = if ($ir.Ms -ge $InformantWarnMs) { " [SLOW]" } else { "" }
                    if ($ir.Error) {
                        [void]$out.Add("    $comp : [ERROR] - $($ir.Error) $msLabel")
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
                        [void]$out.Add("    $comp : [$tag] $msLabel$slowTag")
                        $csInformant[$comp] = [PSCustomObject]@{
                            Status = $tag; Detail = $detail; Ms = $ir.Ms
                            Slow = ($ir.Ms -ge $InformantWarnMs)
                        }
                    }
                }
            } else {
                [void]$out.Add("  [INFO] Skipped Informant checks - service is not running.")
            }

            $allInformant[$cs.Name] = $csInformant

            [void]$csvRows.Add([PSCustomObject]@{
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
        [void]$out.Add("  NOT FOUND")
    }

    # ── Content Server Admin ──────────────────────────────────────────────────
    [void]$out.Add(""); [void]$out.Add("Content Server Admin Service:")
    if ($csAdmin) {
        $autoNote = Invoke-AutoRestart -ServiceName $csAdmin.Name `
            -Computer $ComputerName -CimSession $session -Enabled $AutoRestartStopped
        if ($autoNote) { [void]$out.Add("  [AUTO-RESTART] $autoNote") }

        $csAdminName = $csAdmin.Name
        $csAdmin = Get-CimInstance -CimSession $session -ClassName Win32_Service `
            -Filter "Name='$csAdminName'" -ErrorAction SilentlyContinue

        $caState         = if ($csAdmin.State -eq "Running") { "[RUNNING]" } else { "[STOPPED]" }
        $caUp            = Get-ServiceUptime -CimSession $session -ProcessId $csAdmin.ProcessId
        $caRestartResult = Get-OrSet-RestartConfig -ServiceName $csAdmin.Name -ScHost $scHost
        if ($caRestartResult.LogNote) { [void]$jobLog.Add("[LOG] $($caRestartResult.LogNote)") }
        $caRestart      = $caRestartResult.Display
        $caRestartCount = Get-ServiceRestartCount -ServiceName $csAdmin.Name -Computer $ComputerName
        if ($csAdmin.State -ne "Running") { $overallStatus = "DOWN" }

        [void]$out.Add("  Name:               $($csAdmin.Name)")
        [void]$out.Add("  Status:             $caState")
        [void]$out.Add("  Display Name:       $($csAdmin.DisplayName)")
        [void]$out.Add("  Description:        $($csAdmin.Description)")
        [void]$out.Add("  Run As:             $($csAdmin.StartName)")
        [void]$out.Add("  Service Uptime:     $caUp")
        [void]$out.Add("  Restart Config:     $caRestart")
        [void]$out.Add("  Auto-Restarts(24h): $caRestartCount")

        [void]$csvRows.Add([PSCustomObject]@{
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
        [void]$out.Add("  NOT FOUND")
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
        [void]$log4jScanRoots.Add((Join-Path $tomcatHome "webapps"))
    }

    # Content Server webservices — one per CS instance
    foreach ($cs in $csSvcs) {
        if ($cs.PathName) {
            # PathName may be quoted: "C:\path\to\service.exe" args...
            $exePath = ($cs.PathName -replace '^"?([^"]+\.exe).*$','$1').Trim('"')
            # Walk up: exe -> bin (or similar) -> instance root
            $csRoot = Split-Path (Split-Path $exePath -Parent) -Parent
            $wsDir  = Join-Path $csRoot "webservices"
            [void]$log4jScanRoots.Add($wsDir)
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
            [void]$jobLog.Add("[WARN] Log4j scan failed on $ComputerName (WinRM/Invoke-Command error): $_")
            $log4jFindings = @([PSCustomObject]@{
                ScanRoot = ""; Path = ""; FileName = ""; Version = "ERROR"
                VersionSrc = ""; Status = "SCAN_ERROR"; IsVulnerable = $false
            })
        }
    }

    # Console output for log4j findings
    [void]$out.Add(""); [void]$out.Add("Log4j Scan  (min safe: $Log4jMinSafeVersion):")
    $hasVulnerable = $false
    foreach ($f in $log4jFindings) {
        switch ($f.Status) {
            "VULNERABLE" {
                $hasVulnerable = $true
                [void]$out.Add("  [VULNERABLE] $($f.FileName)  v$($f.Version) (src: $($f.VersionSrc))")
                [void]$out.Add("               Path: $($f.Path)")
                if ($overallStatus -ne "CRITICAL") { $overallStatus = "WARN" }
            }
            "OK" {
                [void]$out.Add("  [OK]         $($f.FileName)  v$($f.Version) (src: $($f.VersionSrc))")
                [void]$out.Add("               Path: $($f.Path)")
            }
            "NOT_FOUND" {
                [void]$out.Add("  [NOT FOUND]  No log4j jars found under: $($f.ScanRoot)")
            }
            "SCAN_ROOT_NOT_FOUND" {
                [void]$out.Add("  [MISSING]    Scan root does not exist: $($f.Path)")
            }
            "UNKNOWN_VERSION" {
                [void]$out.Add("  [UNKNOWN]    $($f.FileName) — version could not be determined")
                [void]$out.Add("               Path: $($f.Path)")
            }
            "SCAN_ERROR" {
                [void]$out.Add("  [ERROR]      Scan failed — check log for details")
            }
        }
    }
    if ($hasVulnerable) {
        [void]$out.Add("  ** VULNERABLE log4j version(s) found — immediate action required **")
    }

    # ── Event log ─────────────────────────────────────────────────────────────
    if ($eventLines.Count -gt 0) {
        [void]$out.Add(""); [void]$out.Add("Recent Application Log Events (last 24h, Tomcat/CS related):")
        foreach ($line in $eventLines) { [void]$out.Add("  $line") }
        if ($overallStatus -eq "OK") { $overallStatus = "WARN" }
    }

    Remove-CimSession $session -ErrorAction SilentlyContinue

    [void]$instanceResults.Add([PSCustomObject]@{
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
$prevCsvs = Get-ChildItem -Path $scriptDir -Filter "ServiceCheck_*.csv" -ErrorAction SilentlyContinue |
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
                if ($prev.Status  -ne $row.Status)  { [void]$deltaDetails.Add("$($row.ServiceName): Status $($prev.Status) -> $($row.Status)") }
                if ($prev.Version -and $prev.Version -ne $row.Version) { [void]$deltaDetails.Add("$($row.ServiceName): Version $($prev.Version) -> $($row.Version)") }
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
$log4jCsvFile = Join-Path $scriptDir ("Log4jScan_" + $timestamp + ".csv")
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

# ── HTML ──────────────────────────────────────────────────────────────────────
$htmlRows = $allCsvRows | Sort-Object Zone, Server, ServiceType
$htmlBody = ""

$htmlRows | Group-Object Zone | ForEach-Object {
    $zoneName   = $_.Name
    $zoneRows   = $_.Group
    $zoneStatus = if   ($zoneRows | Where-Object { $_.OverallStatus -in @("DOWN","CRITICAL") }) { "down" }
                  elseif ($zoneRows | Where-Object { $_.OverallStatus -eq "WARN" }) { "warn" }
                  else { "ok" }
    $zoneId   = $zoneName -replace '[^a-zA-Z0-9]', '_'
    $zoneOK   = ($zoneRows | Where-Object { $_.OverallStatus -eq "OK"       }).Count
    $zoneWarn = ($zoneRows | Where-Object { $_.OverallStatus -eq "WARN"     }).Count
    $zoneCrit = ($zoneRows | Where-Object { $_.OverallStatus -eq "CRITICAL" }).Count
    $zoneDown = ($zoneRows | Where-Object { $_.OverallStatus -eq "DOWN"     }).Count
    $serverHtml = ""

    $zoneRows | Group-Object Server | ForEach-Object {
        $serverName   = $_.Name
        $serverRows   = $_.Group
        $serverStatus = if   ($serverRows | Where-Object { $_.OverallStatus -in @("DOWN","CRITICAL") }) { "down" }
                        elseif ($serverRows | Where-Object { $_.OverallStatus -eq "WARN" }) { "warn" }
                        else { "ok" }
        $serverId     = $zoneId + "_" + ($serverName -replace '[^a-zA-Z0-9]', '_')
        $serverResult = $results | Where-Object { $_.ComputerName -eq $serverName } | Select-Object -First 1

        $csInstanceNames = ($serverRows |
                            Where-Object { $_.ServiceType -eq "ContentServer" } |
                            ForEach-Object { HtmlEncode $_.ServiceName }) -join ", "
        $instSpan = if ($csInstanceNames) {
            "<span class='srv-inst'>$csInstanceNames</span><span class='srv-sep'>/</span>"
        } else { "" }
        $serverHeaderLabel =
            "<span class='srv-zone'>$(HtmlEncode $zoneName)</span>" +
            "<span class='srv-sep'>/</span>" +
            $instSpan +
            "<span class='srv-name'>$(HtmlEncode $serverName)</span>"

        $instanceHtml = ""
        $csRows     = $serverRows | Where-Object { $_.ServiceType -eq "ContentServer" }
        $tomcatRow  = $serverRows | Where-Object { $_.ServiceType -eq "Tomcat" }             | Select-Object -First 1
        $csAdminRow = $serverRows | Where-Object { $_.ServiceType -eq "ContentServerAdmin" } | Select-Object -First 1

        # Log4j findings for this server
        $serverLog4j = @()
        if ($serverResult -and $serverResult.Log4jFindings) {
            $serverLog4j = @($serverResult.Log4jFindings)
        }
        $log4jHtml = ""
        if ($serverLog4j.Count -gt 0) {
            $log4jCells = ""
            foreach ($lf in $serverLog4j) {
                $lfClass = switch ($lf.Status) {
                    "VULNERABLE"          { "error-cell" }
                    "UNKNOWN_VERSION"     { "warn-cell"  }
                    "SCAN_ROOT_NOT_FOUND" { "warn-cell"  }
                    "SCAN_ERROR"          { "error-cell" }
                    default               { ""           }
                }
                $lfLabel = switch ($lf.Status) {
                    "OK"                  { "OK"          }
                    "VULNERABLE"          { "VULNERABLE"  }
                    "NOT_FOUND"           { "Not found"   }
                    "SCAN_ROOT_NOT_FOUND" { "Path missing" }
                    "UNKNOWN_VERSION"     { "Unknown ver" }
                    "SCAN_ERROR"          { "Scan error"  }
                    default               { $lf.Status    }
                }
                $lfChipClass = switch ($lf.Status) {
                    "OK"      { "ok"      }
                    "VULNERABLE" { "critical" }
                    default   { "warn"    }
                }
                $lfDetail = if ($lf.FileName) {
                    "$(HtmlEncode $lf.FileName)  v$(HtmlEncode $lf.Version)  <span class='text-muted'>($(HtmlEncode $lf.VersionSrc))</span><br><span class='text-muted' style='font-size:10px'>$(HtmlEncode $lf.Path)</span>"
                } elseif ($lf.ScanRoot) {
                    "<span class='text-muted'>$(HtmlEncode $lf.ScanRoot)</span>"
                } else { "" }
                $log4jCells += "<div class='detail-cell $lfClass full-width'>" +
                    "<div class='d-label'>Log4j <span class='chip $lfChipClass' style='font-size:9px;padding:1px 6px'>$lfLabel</span></div>" +
                    "<div class='d-value'>$lfDetail</div></div>"
            }
            $log4jHtml = $log4jCells
        }

        $csRows | ForEach-Object {
            $primary  = $_
            $instName = $primary.ServiceName
            $sc = switch ($primary.OverallStatus) {
                "OK"{"ok"} "WARN"{"warn"} "CRITICAL"{"critical"} "DOWN"{"down"} default {""}
            }
            $instId = $serverId + "_" + ($instName -replace '[^a-zA-Z0-9]', '_')
            $detId  = $instId + "_det"
            $infId  = $instId + "_inf"

            function fmtChip { param($t,$c) "<span class='chip $c'>$t</span>" }

            $statusChip  = if ($primary.Status -eq "Running") { fmtChip "RUNNING" "running" }
                           else { fmtChip "STOPPED" "stopped" }
            $overallChip = switch ($primary.OverallStatus) {
                "OK"       { fmtChip "OK"       "ok"       }
                "WARN"     { fmtChip "WARN"      "warn"     }
                "CRITICAL" { fmtChip "CRITICAL"  "critical" }
                "DOWN"     { fmtChip "DOWN"       "down"    }
                default    { fmtChip (HtmlEncode $primary.OverallStatus) "na" }
            }
            $versionVal = if ($tomcatRow -and $tomcatRow.Version)     { HtmlEncode $tomcatRow.Version }      else { "N/A" }
            $wsVal      = if ($tomcatRow -and $tomcatRow.WorkingSetMB) { HtmlEncode $tomcatRow.WorkingSetMB } else { "N/A" }
            $heapVal    = if ($tomcatRow -and $tomcatRow.HeapInitMB) {
                              "Xms: $(HtmlEncode $tomcatRow.HeapInitMB) MB / Xmx: $(HtmlEncode $tomcatRow.HeapMaxMB) MB"
                          } else { "N/A" }
            $cpuChipClass = if ([double]$primary.CpuPct -ge 90) {"critical"} elseif ([double]$primary.CpuPct -ge 75) {"warn"} else {"ok"}
            $memChipClass = if ([double]$primary.MemPct -ge 90) {"critical"} elseif ([double]$primary.MemPct -ge 75) {"warn"} else {"ok"}

            # Detail grid
            $detCells = ""
            if ($serverResult) {
                $detCells += "<div class='detail-cell'><div class='d-label'>Server Uptime</div><div class='d-value'>$(HtmlEncode $serverResult.Uptime)</div></div>"
                $detCells += "<div class='detail-cell'><div class='d-label'>Memory</div><div class='d-value'>$($serverResult.MemUsedGB) GB / $($serverResult.MemTotalGB) GB ($($serverResult.MemPct)%)</div></div>"
                $detCells += "<div class='detail-cell'><div class='d-label'>CPU (avg)</div><div class='d-value'>$($serverResult.CpuAvg)%</div></div>"
                $detCells += "<div class='detail-cell full-width'><div class='d-label'>Drives</div><div class='d-value'>$(HtmlEncode $serverResult.DrivesSummary)</div></div>"
                foreach ($de in $serverResult.DriveErrors) {
                    $detCells += "<div class='detail-cell error-cell full-width'><div class='d-label'>Drive Critical</div><div class='d-value'>$(HtmlEncode $de)</div></div>"
                }
                foreach ($dw in $serverResult.DriveWarnings) {
                    $detCells += "<div class='detail-cell warn-cell full-width'><div class='d-label'>Drive Warning</div><div class='d-value'>$(HtmlEncode $dw)</div></div>"
                }
            }
            $detCells += "<div class='detail-cell'><div class='d-label'>Run As</div><div class='d-value'>$(HtmlEncode $primary.RunAs)</div></div>"
            $detCells += "<div class='detail-cell'><div class='d-label'>Service Uptime</div><div class='d-value'>$(HtmlEncode $primary.ServiceUptime)</div></div>"
            $detCells += "<div class='detail-cell'><div class='d-label'>Restart Config</div><div class='d-value'>$(HtmlEncode $primary.RestartConfig)</div></div>"
            $autoRestartStr = "$($primary.AutoRestarts)"
            $detCells += "<div class='detail-cell'><div class='d-label'>Auto-Restarts (24h)</div><div class='d-value'>$(HtmlEncode $autoRestartStr)</div></div>"

            if ($tomcatRow) {
                $detCells += "<div class='detail-cell'><div class='d-label'>Tomcat Service</div><div class='d-value'>$(HtmlEncode $tomcatRow.ServiceName)</div></div>"
                $detCells += "<div class='detail-cell'><div class='d-label'>Tomcat Version</div><div class='d-value'>$(HtmlEncode $tomcatRow.Version)</div></div>"
                $detCells += "<div class='detail-cell full-width'><div class='d-label'>JRE Path</div><div class='d-value'>$(HtmlEncode $tomcatRow.JrePath)</div></div>"
                $heapXmsDisplay = if ($tomcatRow.HeapInitMB) { "$($tomcatRow.HeapInitMB) MB" } else { 'N/A' }
                $detCells += "<div class='detail-cell'><div class='d-label'>Heap Xms</div><div class='d-value'>$heapXmsDisplay</div></div>"
                $heapXmxDisplay = if ($tomcatRow.HeapMaxMB) { "$($tomcatRow.HeapMaxMB) MB" } else { 'N/A' }
                $detCells += "<div class='detail-cell'><div class='d-label'>Heap Xmx</div><div class='d-value'>$heapXmxDisplay</div></div>"
                $detCells += "<div class='detail-cell'><div class='d-label'>Working Set</div><div class='d-value'>$(HtmlEncode $tomcatRow.WorkingSetMB)</div></div>"
                $gcCls = if ($serverResult -and $serverResult.GcWarnings -and $serverResult.GcWarnings.Count -gt 0) { "warn-cell" } else { "" }
                $detCells += "<div class='detail-cell $gcCls'><div class='d-label'>GC Collector</div><div class='d-value'>$(HtmlEncode $tomcatRow.GcCollector)</div></div>"
                if ($serverResult -and $serverResult.GcWarnings) {
                    foreach ($gw in $serverResult.GcWarnings) {
                        $detCells += "<div class='detail-cell warn-cell full-width'><div class='d-label'>GC Warning</div><div class='d-value'>$(HtmlEncode $gw)</div></div>"
                    }
                }
                if ($serverResult -and $serverResult.GcRecommend -and $serverResult.GcRecommend.Count -gt 0) {
                    $recHtml = "<ol style='margin:4px 0 0 16px;padding:0'>"
                    foreach ($gr in $serverResult.GcRecommend) { $recHtml += "<li style='margin-bottom:4px'>$(HtmlEncode $gr)</li>" }
                    $recHtml += "</ol>"
                    $detCells += "<div class='detail-cell full-width' style='background:#0d1320;border-left:3px solid #1f6feb'>" +
                                 "<div class='d-label' style='color:#79c0ff'>GC Recommendations</div>" +
                                 "<div class='d-value' style='color:#c9d1d9;font-family:inherit'>$recHtml</div></div>"
                }
            }
            if ($csAdminRow) {
                $detCells += "<div class='detail-cell'><div class='d-label'>CS Admin</div><div class='d-value'>$(HtmlEncode $csAdminRow.ServiceName) [$(HtmlEncode $csAdminRow.Status)]</div></div>"
            }
            if ($serverResult -and $serverResult.EventLines -and $serverResult.EventLines.Count -gt 0) {
                $evText = ($serverResult.EventLines | ForEach-Object { HtmlEncode $_ }) -join "<br>"
                $detCells += "<div class='detail-cell warn-cell full-width'><div class='d-label'>Event Log (24h)</div><div class='d-value'>$evText</div></div>"
            }
            foreach ($row in $serverRows) {
                $key  = "$($row.Server)|$($row.ServiceName)"; $prev = $prevData[$key]
                if ($prev -and ($prev.Status -ne $row.Status -or ($prev.Version -and $prev.Version -ne $row.Version))) {
                    $chg  = if ($prev.Status  -ne $row.Status)  { "Status: $(HtmlEncode $prev.Status) &rarr; $(HtmlEncode $row.Status)" } else { "" }
                    $chgV = if ($prev.Version -and $prev.Version -ne $row.Version) { " Version: $(HtmlEncode $prev.Version) &rarr; $(HtmlEncode $row.Version)" } else { "" }
                    $detCells += "<div class='detail-cell changed-cell full-width'><div class='d-label'>Changed</div><div class='d-value'>$(HtmlEncode $row.ServiceName): $chg$chgV</div></div>"
                }
            }
            # Append log4j findings to detail panel
            $detCells += $log4jHtml

            # Informant grid
            $infCells = ""; $infHasIssues = $false; $infOkCount = 0; $infToggleHtml = ""
            if ($serverResult -and $serverResult.InformantResults -and
                $serverResult.InformantResults.Contains($instName)) {
                foreach ($comp in $serverResult.InformantResults[$instName].Keys) {
                    $ir      = $serverResult.InformantResults[$instName][$comp]
                    $slowBit = if ($ir.Slow) { " <span class='chip slow'>SLOW</span>" } else { "" }
                    $chipCls = switch ($ir.Status) {
                        "SUCCESS"{"ok"} "FAILURE"{"failure"} "ERROR"{"error"} default{"other"}
                    }
                    if ($ir.Status -ne "SUCCESS") { $infHasIssues = $true } else { $infOkCount++ }
                    $detail = if ($ir.Status -notin @("SUCCESS","FAILURE")) {
                                  "<span class='text-muted' style='font-size:10px'>$(HtmlEncode $ir.Detail)</span>"
                              } else { "" }
                    $infCells += "<div class='inf-cell'>" +
                                 "<span class='inf-comp'>$(HtmlEncode $comp)</span>" +
                                 "<span class='chip $chipCls'>$(HtmlEncode $ir.Status)</span>$slowBit$detail" +
                                 "<span class='inf-ms'>$($ir.Ms)ms</span></div>"
                }
                $infLabel = if ($infHasIssues) { "Informant  Issues detected" } else { "Informant  $infOkCount OK" }
                $infToggleHtml = "<tr><td colspan='10'>" +
                    "<div class='inf-toggle collapsed' onclick='toggleRow(this,&quot;$infId&quot;)' data-target='$infId'>" +
                    "<span class='arrow'>v</span> $infLabel</div>" +
                    "<div id='$infId' class='hidden-panel'><div class='inf-grid'>$infCells</div></div>" +
                    "</td></tr>"
            }

            $instanceHtml += "
            <tr class='instance-header $sc' onclick='toggleRow(this, &quot;$detId&quot;)'>
              <td style='padding:8px 12px'><span class='arrow'>v</span></td>
              <td><span class='inst-label'><span class='inst-name-text'>$(HtmlEncode $instName)</span></span></td>
              <td>$statusChip</td>
              <td class='monospace' style='padding:8px 12px;font-size:12px'>$versionVal</td>
              <td class='monospace' style='padding:8px 12px;font-size:12px'>$wsVal</td>
              <td class='monospace' style='padding:8px 12px;font-size:12px'>$heapVal</td>
              <td>$(fmtChip "$($primary.CpuPct)%" $cpuChipClass)</td>
              <td>$(fmtChip "$($primary.MemPct)%" $memChipClass)</td>
              <td style='padding:8px 12px;font-size:12px'>$(HtmlEncode "$($primary.AutoRestarts)")</td>
              <td>$overallChip</td>
            </tr>
            <tr id='$detId' style='display:none'><td colspan='10' style='padding:0'>
              <div class='detail-panel'><div class='detail-grid'>$detCells</div></div>
            </td></tr>
            $infToggleHtml"
        }

        $serverHtml += "
        <tr class='server-header $serverStatus' onclick='toggleRow(this, &quot;$serverId&quot;)'>
          <td colspan='10'><div class='server-label'><span class='arrow'>v</span>$serverHeaderLabel</div></td>
        </tr>
        <tbody id='$serverId' class='collapsible'>
          <tr><td colspan='10' style='padding:0'>
            <table class='inner-table'>
              <thead><tr>
                <th style='width:32px'></th>
                <th>Instance</th><th>Status</th><th>Version</th>
                <th>Working Set</th><th>Heap Xms/Xmx</th>
                <th>CPU%</th><th>Mem%</th><th>Restarts</th><th>Overall</th>
              </tr></thead>
              <tbody>$instanceHtml</tbody>
            </table>
          </td></tr>
        </tbody>"
    }

    $htmlBody += "
    <tr class='zone-header $zoneStatus' onclick='toggleRow(this, &quot;$zoneId&quot;)'>
      <td colspan='10'>
        <div class='zone-label'>
          <span class='arrow'>v</span>
          <span class='z-name'>$(HtmlEncode $zoneName)</span>
          <span class='z-counts'>$zoneOK OK / $zoneWarn WARN / $zoneCrit CRIT / $zoneDown DOWN</span>
        </div>
      </td>
    </tr>
    <tbody id='$zoneId' class='collapsible'>$serverHtml</tbody>"
}

$zoneRollupHtml = foreach ($grp in $zoneSummary.Keys) {
    $s   = $zoneSummary[$grp]
    $cls = if ($s.DOWN -gt 0 -or $s.CRITICAL -gt 0) { "crit" } elseif ($s.WARN -gt 0) { "warn" } else { "ok" }
    "<div class='zone-pill $cls'>" +
    "<span class='pill-name'>$(HtmlEncode $grp)</span>" +
    "<span class='pill-counts'>$($s.OK) OK / $($s.WARN) W / $($s.CRITICAL) C / $($s.DOWN) D</span>" +
    "</div>"
}

# Log4j summary panel for HTML
$log4jSummaryHtml = ""
if ($allLog4j -and @($allLog4j).Count -gt 0) {
    $vulnCount    = @($allLog4j | Where-Object { $_.IsVulnerable }).Count
    $panelClass   = if ($vulnCount -gt 0) { "error-cell" } else { "detail-cell" }
    $scanSummary  = "<div class='$panelClass' style='padding:12px 16px;margin-bottom:16px;border-radius:8px;border:1px solid #21262d'>"
    $scanSummary += "<div class='d-label' style='font-size:12px;margin-bottom:8px'>Log4j Scan Summary"
    $chipClass    = if ($vulnCount -gt 0) { 'critical' } else { 'ok' }
    $chipLabel    = if ($vulnCount -gt 0) { "$vulnCount VULNERABLE" } else { 'Clean' }
    $scanSummary += "  <span class='chip $chipClass'>$chipLabel</span>"
    $scanSummary += "  <span class='text-muted' style='font-size:10px;font-weight:400'>min safe: $Log4jMinSafeVersion</span></div>"
    if ($vulnCount -gt 0) {
        $scanSummary += "<div class='d-value'>"
        foreach ($vf in ($allLog4j | Where-Object { $_.IsVulnerable })) {
            $scanSummary += "$(HtmlEncode $vf.FileName)  v$(HtmlEncode $vf.Version)  &mdash;  $(HtmlEncode $vf.Path)<br>"
        }
        $scanSummary += "</div>"
    }
    $scanSummary += "</div>"
    $log4jSummaryHtml = $scanSummary
}

$htmlContent = @"
<!DOCTYPE html>
<html lang='en'><head><meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Service Check Report - $timestamp</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #c9d1d9; min-height: 100vh; padding: 24px; }
  .page-header { display: flex; align-items: center; gap: 16px; margin-bottom: 28px; padding-bottom: 20px; border-bottom: 1px solid #21262d; }
  .page-header .logo { width: 42px; height: 42px; background: linear-gradient(135deg, #238636, #2ea043); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 22px; flex-shrink: 0; }
  .page-header h1 { font-size: 22px; font-weight: 700; color: #e6edf3; letter-spacing: -0.3px; }
  .page-header .subtitle { font-size: 13px; color: #8b949e; margin-top: 2px; }
  .header-right { margin-left: auto; text-align: right; }
  .run-time { font-size: 12px; color: #8b949e; }
  .run-time strong { color: #c9d1d9; }
  .stat-bar { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 28px; }
  .stat-card { background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 14px 22px; min-width: 110px; text-align: center; }
  .stat-card .stat-num { font-size: 28px; font-weight: 700; line-height: 1; margin-bottom: 4px; }
  .stat-card .stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: #8b949e; }
  .stat-card.ok .stat-num { color: #3fb950; } .stat-card.warn .stat-num { color: #d29922; }
  .stat-card.crit .stat-num { color: #f85149; } .stat-card.down .stat-num { color: #f85149; }
  .stat-card.total .stat-num { color: #79c0ff; }
  .section-title { font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.07em; color: #8b949e; margin-bottom: 12px; }
  .zone-pills { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 28px; }
  .zone-pill { display: inline-flex; align-items: center; gap: 8px; padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 600; border: 1px solid transparent; }
  .zone-pill .pill-name { color: #e6edf3; } .zone-pill .pill-counts { font-size: 11px; opacity: 0.8; }
  .zone-pill.ok { background: #0d1f12; border-color: #238636; }
  .zone-pill.warn { background: #1f1a0d; border-color: #9e6a03; }
  .zone-pill.crit { background: #1f0d0d; border-color: #da3633; }
  .table-wrap { background: #161b22; border: 1px solid #21262d; border-radius: 12px; overflow: hidden; }
  table { border-collapse: collapse; width: 100%; }
  th { background: #1c2128; color: #8b949e; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; padding: 10px 14px; text-align: left; border-bottom: 1px solid #21262d; white-space: nowrap; }
  td { padding: 0; border: none; font-size: 13px; }
  .zone-header td { padding: 11px 16px; font-size: 13px; font-weight: 700; cursor: pointer; background: #1c2128; border-top: 2px solid #21262d; border-bottom: 1px solid #21262d; user-select: none; }
  .zone-header.ok td { border-left: 3px solid #238636; } .zone-header.warn td { border-left: 3px solid #9e6a03; }
  .zone-header.down td, .zone-header.critical td { border-left: 3px solid #da3633; }
  .zone-label { display: flex; align-items: center; gap: 10px; }
  .zone-label .z-name { color: #79c0ff; font-size: 13px; } .zone-label .z-counts { font-size: 11px; color: #8b949e; font-weight: 400; }
  .server-header td { padding: 9px 16px 9px 28px; cursor: pointer; background: #161b22; border-bottom: 1px solid #21262d; user-select: none; }
  .server-header.ok td { border-left: 3px solid #238636; } .server-header.warn td { border-left: 3px solid #9e6a03; }
  .server-header.down td, .server-header.critical td { border-left: 3px solid #da3633; }
  .server-label { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .srv-zone { font-size: 11px; color: #8b949e; font-weight: 400; } .srv-inst { font-size: 13px; color: #3fb950; font-weight: 700; }
  .srv-name { font-size: 13px; color: #c9d1d9; } .srv-sep { color: #30363d; font-size: 13px; }
  .inner-table { width: 100%; border-collapse: collapse; }
  .inner-table th { background: #0d1117; padding: 8px 12px; font-size: 10px; }
  .instance-header td { padding: 8px 12px; cursor: pointer; background: #0f1117; border-bottom: 1px solid #21262d; user-select: none; font-size: 12px; }
  .instance-header:hover td { background: #161b22; }
  .inst-label { display: flex; align-items: center; gap: 6px; }
  .inst-name-text { color: #e6edf3; font-weight: 600; }
  .chip { display: inline-block; padding: 2px 9px; border-radius: 12px; font-size: 11px; font-weight: 700; letter-spacing: 0.04em; white-space: nowrap; }
  .chip.ok, .chip.running { background: #0d1f12; color: #3fb950; border: 1px solid #238636; }
  .chip.warn { background: #1f1a0d; color: #d29922; border: 1px solid #9e6a03; }
  .chip.critical, .chip.failure, .chip.stopped, .chip.down, .chip.error { background: #1f0d0d; color: #f85149; border: 1px solid #da3633; }
  .chip.other { background: #1a1f2e; color: #79c0ff; border: 1px solid #1f6feb; }
  .chip.slow { background: #1f1508; color: #e3b341; border: 1px solid #bb8009; }
  .chip.na { background: #161b22; color: #8b949e; border: 1px solid #30363d; }
  .detail-panel { background: #0d1117; border-bottom: 1px solid #21262d; }
  .detail-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 1px; background: #21262d; border-top: 1px solid #21262d; }
  .detail-cell { background: #0d1117; padding: 8px 16px; display: flex; flex-direction: column; gap: 2px; }
  .detail-cell .d-label { font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: #8b949e; }
  .detail-cell .d-value { font-size: 12px; color: #c9d1d9; word-break: break-all; font-family: 'Cascadia Code', 'Consolas', monospace; }
  .detail-cell.full-width { grid-column: 1 / -1; }
  .detail-cell.error-cell { background: #130a0a; } .detail-cell.error-cell .d-label { color: #f85149; } .detail-cell.error-cell .d-value { color: #f85149; font-weight: 600; }
  .detail-cell.warn-cell { background: #13100a; } .detail-cell.warn-cell .d-label { color: #d29922; } .detail-cell.warn-cell .d-value { color: #d29922; }
  .detail-cell.changed-cell { background: #130f00; } .detail-cell.changed-cell .d-label { color: #e3b341; } .detail-cell.changed-cell .d-value { color: #e3b341; }
  .inf-toggle { display: flex; align-items: center; gap: 8px; padding: 7px 16px; cursor: pointer; background: #0d1117; border-top: 1px solid #21262d; border-bottom: 1px solid #21262d; user-select: none; font-size: 12px; font-weight: 600; color: #79c0ff; }
  .inf-toggle:hover { background: #161b22; }
  .inf-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 1px; background: #21262d; }
  .inf-cell { background: #0a0d13; padding: 7px 14px; display: flex; align-items: center; gap: 8px; }
  .inf-cell .inf-comp { font-size: 11px; font-weight: 600; color: #8b949e; width: 100px; flex-shrink: 0; font-family: 'Cascadia Code', 'Consolas', monospace; }
  .inf-cell .inf-ms { font-size: 10px; color: #484f58; margin-left: auto; }
  .arrow { display: inline-block; width: 16px; height: 16px; flex-shrink: 0; border-radius: 4px; background: #21262d; text-align: center; line-height: 16px; font-size: 9px; color: #8b949e; transition: transform 0.18s ease, background 0.15s; font-style: normal; }
  .collapsed .arrow { transform: rotate(-90deg); }
  .collapsible { display: table-row-group; } .hidden-panel { display: none; }
  .monospace { font-family: 'Cascadia Code', 'Consolas', monospace; } .text-muted { color: #8b949e; } .mt-16 { margin-top: 16px; }
</style></head><body>
<div class='page-header'>
  <div class='logo'>S</div>
  <div><h1>Service Check Report</h1><div class='subtitle'>Tomcat / Content Server / CS Admin</div></div>
  <div class='header-right'>
    <div class='run-time'><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
    <div class='run-time'><strong>Servers:</strong> $serverCount &nbsp;|&nbsp; <strong>Auto-restart:</strong> $(if ($AutoRestartStopped) { 'On' } else { 'Off' })</div>
  </div>
</div>
$log4jSummaryHtml
<div class='stat-bar' id='stat-bar'></div>
<p class='section-title'>Zones</p>
<div class='zone-pills'>$($zoneRollupHtml -join '')</div>
<p class='section-title mt-16'>Detail</p>
<div class='table-wrap'>
<table id='main-table'>
  <thead><tr>
    <th style='width:32px'></th><th>Instance</th><th>Status</th><th>Version</th>
    <th>Working Set</th><th>Heap Xms/Xmx</th><th>CPU%</th><th>Mem%</th><th>Restarts</th><th>Overall</th>
  </tr></thead>
  <tbody>$htmlBody</tbody>
</table>
</div>
<script>
function toggleRow(h, id) {
    var el = document.getElementById(id);
    if (!el) return;
    var hidden = el.style.display === 'none' || el.classList.contains('hidden-panel');
    el.style.display = (el.tagName === 'TBODY') ? (hidden ? 'table-row-group' : 'none') : (hidden ? 'block' : 'none');
    h.classList.toggle('collapsed', !hidden);
}
window.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.collapsible').forEach(function(e){ e.style.display='none'; });
    document.querySelectorAll('.hidden-panel').forEach(function(e){ e.style.display='none'; });
    document.querySelectorAll('.zone-header,.server-header,.instance-header,.inf-toggle').forEach(function(r){ r.classList.add('collapsed'); });
    var sel = ['.zone-header.warn','.zone-header.down','.zone-header.critical',
               '.server-header.warn','.server-header.down','.server-header.critical',
               '.instance-header.warn','.instance-header.down','.instance-header.critical'].join(',');
    document.querySelectorAll(sel).forEach(function(row){
        var next = row.nextElementSibling;
        while (next && next.tagName !== 'TBODY') { next = next.nextElementSibling; }
        if (next) { next.style.display = 'table-row-group'; row.classList.remove('collapsed'); }
    });
    document.querySelectorAll('.inf-toggle').forEach(function(row){
        var id = row.getAttribute('data-target');
        var el = id ? document.getElementById(id) : null;
        if (el && el.querySelector('.chip.failure,.chip.error')) { el.style.display='block'; row.classList.remove('collapsed'); }
    });
    var ok=0, warn=0, crit=0, down=0;
    document.querySelectorAll('.instance-header').forEach(function(r){
        if (r.classList.contains('ok')) ok++;
        else if (r.classList.contains('warn')) warn++;
        else if (r.classList.contains('critical')) crit++;
        else if (r.classList.contains('down')) down++;
    });
    document.getElementById('stat-bar').innerHTML =
        mk(ok+warn+crit+down,'Total','total')+mk(ok,'Healthy','ok')+mk(warn,'Warning','warn')+mk(crit,'Critical','crit')+mk(down,'Down','down');
});
function mk(n,l,c){ return "<div class='stat-card "+c+"'><div class='stat-num'>"+n+"</div><div class='stat-label'>"+l+"</div></div>"; }
</script>
</body></html>
"@

try {
    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($htmlFile, $htmlContent, $utf8Bom)
    Write-Log "HTML report    : $htmlFile" -Color Green
} catch {
    Write-Log "WARNING: WriteAllText failed for HTML ($_ ) -- retrying with Out-File..." -Color Yellow
    try {
        $htmlContent | Out-File -FilePath $htmlFile -Encoding utf8 -Force
        Write-Log "HTML report    : $htmlFile (written via Out-File)" -Color Green
    } catch {
        Write-Log "ERROR: Could not write HTML report to '$htmlFile' -- $_" -Color Red
    }
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
Write-Log "HTML     : $htmlFile"       -Color Green
Write-Log "Log4j CSV: $log4jCsvFile"   -Color Green
#endregion

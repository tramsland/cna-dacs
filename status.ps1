#Requires -Version 5.1
# Remote Service Status Checker (Parallel with Logging)
# Checks Tomcat, Content Server, and Content Server Admin on remote Windows servers
# v4.0 -- tile-based HTML report, CS version lookup, per-service uptimes

#region Parameters
param(
    [switch]$QuietOK,
    [string]$SmtpServer          = "smtp.domain.com",
    [string]$EmailFrom           = "monitoring@domain.com",
    [string]$EmailTo             = "ops@domain.com",
    [string]$TeamsWebhookUrl     = "",
    [switch]$AutoRestartStopped,
    [int]$InformantWarnMs        = 5000,
    [int]$MaxParallelJobs        = 10
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
            $serverGroups[$currentGroup] = [System.Collections.Generic.List[string]]::new()
        }
        continue
    }
    if (-not $serverGroups.Contains($currentGroup)) {
        $serverGroups[$currentGroup] = [System.Collections.Generic.List[string]]::new()
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

#region Script block (runs inside each parallel job)
$checkServicesScript = {
    param(
        [string]$ComputerName,
        [string]$GroupName,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$WebTimeoutSec,
        [int]$InformantWarnMs,
        [int]$EventLogCount,
        [int]$PortCheckTimeout,
        [bool]$AutoRestartStopped
    )

    # ── Inline helpers ─────────────────────────────────────────────────────────
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

    # Reads the ProductVersion from livelink.exe via UNC path (avoids nested Invoke-Command).
    # PathName is like:  "E:\customers\dacs\DACS_CS1\bin\livelink.exe" ...
    # We convert the drive letter to a UNC admin share: \\server\E$\path\livelink.exe
    # Get-CsVersion: runs on the REMOTE machine via Invoke-Command so the local
    # path in PathName (e.g. E:\customers\dacs\CS1\bin\livelink.exe) resolves correctly.
    function Get-CsVersion {
        param([string]$ServiceImagePath, [string]$Computer,
              [System.Management.Automation.PSCredential]$Cred)
        $icArgs = @{
            ComputerName = $Computer
            ErrorAction  = "Stop"
            ArgumentList = $ServiceImagePath
            ScriptBlock  = {
                param([string]$ImagePath)
                # Strip surrounding quotes if present
                $exePath = $null
                if ($ImagePath -match '^\s*"?([^"]+livelink\.exe)"?\s*$') {
                    $exePath = $Matches[1].Trim()
                } elseif ($ImagePath -match '^\s*"?([A-Za-z]:\\[^"]+\.exe)"?\s*$') {
                    $exePath = $Matches[1].Trim()
                }
                if (-not $exePath -or -not (Test-Path $exePath -ErrorAction SilentlyContinue)) {
                    return "N/A"
                }
                try {
                    $vi = (Get-Item $exePath -ErrorAction Stop).VersionInfo
                    # Prefer ProductVersion; fall back to FileVersion
                    $ver = if ($vi.ProductVersion) { $vi.ProductVersion } else { $vi.FileVersion }
                    return if ($ver) { $ver.Trim() } else { "N/A" }
                } catch { return "N/A" }
            }
        }
        if ($Cred) { $icArgs["Credential"] = $Cred }
        try { return Invoke-Command @icArgs } catch { return "N/A" }
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
            return if ($evts) { $evts.Count } else { 0 }
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

    $instanceResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $jobLog          = [System.Collections.Generic.List[string]]::new()
    $scHost          = $ComputerName -replace "\..*", ""

    # ── Ping ───────────────────────────────────────────────────────────────────
    $pingOk = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (-not $pingOk) {
        $out = [System.Collections.Generic.List[string]]::new()
        $out.Add(""); $out.Add("========================================")
        $out.Add("Zone     : $GroupName"); $out.Add("Server   : $ComputerName")
        $out.Add("  ERROR: Host unreachable (no ping response) - skipping.")
        $out.Add("========================================")
        $instanceResults.Add([PSCustomObject]@{
            ComputerName = $ComputerName; GroupName = $GroupName
            InstanceLabel = "N/A"; Output = $out; CsvRows = $null
            OverallStatus = "DOWN"; TomcatVersion = $null
            EventLines = @(); DriveErrors = @(); DriveWarnings = @(); InformantResults = @{}
            GcCollector = "N/A"; GcWarnings = @(); GcRecommend = @()
            MemPct = 0; CpuAvg = 0; MemUsedGB = 0; MemTotalGB = 0
            MemFreeGB = 0; DrivesSummary = ""; Uptime = "N/A"; JobLog = $jobLog
        })
        return $instanceResults
    }

    # ── CIM session ────────────────────────────────────────────────────────────
    $cimParams = @{ ComputerName = $ComputerName; ErrorAction = "Stop" }
    if ($Credential) { $cimParams["Credential"] = $Credential }
    try { $session = New-CimSession @cimParams }
    catch {
        $out = [System.Collections.Generic.List[string]]::new()
        $out.Add(""); $out.Add("========================================")
        $out.Add("Zone     : $GroupName"); $out.Add("Server   : $ComputerName")
        $out.Add("  ERROR: Could not open CIM session - $_")
        $out.Add("========================================")
        $instanceResults.Add([PSCustomObject]@{
            ComputerName = $ComputerName; GroupName = $GroupName
            InstanceLabel = "N/A"; Output = $out; CsvRows = $null
            OverallStatus = "DOWN"; TomcatVersion = $null
            EventLines = @(); DriveErrors = @(); DriveWarnings = @(); InformantResults = @{}
            GcCollector = "N/A"; GcWarnings = @(); GcRecommend = @()
            MemPct = 0; CpuAvg = 0; MemUsedGB = 0; MemTotalGB = 0
            MemFreeGB = 0; DrivesSummary = ""; Uptime = "N/A"; JobLog = $jobLog
        })
        return $instanceResults
    }

    # ── System data ────────────────────────────────────────────────────────────
    $os         = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -ErrorAction Stop
    $allCimSvcs = Get-CimInstance -CimSession $session -ClassName Win32_Service          -ErrorAction Stop
    $allDisks   = Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk `
                      -Filter "DriveType=3" -ErrorAction SilentlyContinue | Sort-Object DeviceID
    $cpuAvg     = Get-CpuPercent -CimSession $session

    $totalMemGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeMemGB  = [math]::Round($os.FreePhysicalMemory      / 1MB, 2)
    $usedMemGB  = [math]::Round($totalMemGB - $freeMemGB, 2)
    $memPct     = if ($totalMemGB -gt 0) { [math]::Round(($usedMemGB / $totalMemGB) * 100, 1) } else { 0 }
    $uptimeStr  = Get-UptimeString -LastBootTime $os.LastBootUpTime
    $recentTag  = if (((Get-Date) - $os.LastBootUpTime).TotalHours -lt 24) { "  [WARN - Recent Reboot]" } else { "" }

    # Drive info
    $driveErrors   = [System.Collections.Generic.List[string]]::new()
    $driveWarnings = [System.Collections.Generic.List[string]]::new()
    $drivesSummaryForCsv = ($allDisks | ForEach-Object {
        $t = [math]::Round($_.Size / 1GB, 2)
        $f = [math]::Round($_.FreeSpace / 1GB, 2)
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
            $tag    = Get-ThresholdTag -Pct $pct
            $prefix = if ($pct -ge 90) { "[DRIVE_CRITICAL] " } else { "" }
            ($prefix + "    " + $_.DeviceID + "  " + (Get-VisualBar -Pct $pct) + " " + $pct + "% used  (" +
             $usedGB + " GB / " + $totGB + " GB)  Free: " + $freeGB + " GB" + $tag)
        }) -join "`n"
    } else { "    No fixed drives found." }

    # ── Event log scan ─────────────────────────────────────────────────────────
    $eventLines = [System.Collections.Generic.List[string]]::new()
    try {
        $recentEvents = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
            LogName   = "Application"
            Level     = @(1, 2, 3)
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

    # ── Locate services ────────────────────────────────────────────────────────
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

    # ── Tomcat version + JVM config ────────────────────────────────────────────
    $tomcatVersion = "N/A"
    $jrePath       = "N/A"
    $heapInitMB    = $null
    $heapMaxMB     = $null
    $gcCollector   = "N/A"
    $gcWarnings    = [System.Collections.Generic.List[string]]::new()
    $gcRecommend   = [System.Collections.Generic.List[string]]::new()

    if ($tomcatSvc) {
        $icParams = @{
            ComputerName = $ComputerName
            ErrorAction  = "Stop"
            ArgumentList = $tomcatSvc.Name, $tomcatSvc.PathName, $tomcatSvc.ProcessId
            ScriptBlock  = {
                param([string]$SvcName, [string]$ImagePath, [int]$ProcessId)

                $tomcatHome    = $null
                $tomcatVersion = "Unknown"
                $jrePath       = "N/A"
                $heapInitMB    = $null
                $heapMaxMB     = $null

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
                                'K' { [math]::Round($val / 1KB, 0) } 'M' { $val } 'G' { $val * 1024 }
                            }
                        }
                        if ($optFlat -match '(?:^|\s)-Xmx(\d+)([kmgKMG])') {
                            $val = [long]$Matches[1]
                            $heapMaxMB = switch ($Matches[2].ToUpper()) {
                                'K' { [math]::Round($val / 1KB, 0) } 'M' { $val } 'G' { $val * 1024 }
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
                                    $rdr     = New-Object System.IO.StreamReader($entry.Open())
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

                $gcCollector = "Unknown"
                $gcFlags     = @{}
                $gcWarnings  = [System.Collections.Generic.List[string]]::new()
                $gcRecommend = [System.Collections.Generic.List[string]]::new()
                $flagLines   = @()
                $jcmdPath    = $null

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
                } elseif (-not $jcmdPath) {
                    $gcCollector = "jcmd not found (JRE-only install?)"
                } elseif ($ProcessId -le 0) {
                    $gcCollector = "N/A (service not running)"
                }

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
                        $gcRecommend.Add("Consider reducing Xmx to ~$([math]::Round($totalRamMB * 0.45,0)) MB (~45% of RAM)")
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
                    Version     = $tomcatVersion
                    JrePath     = $jrePath
                    HeapInitMB  = $heapInitMB
                    HeapMaxMB   = $heapMaxMB
                    GcCollector = $gcCollector
                    GcWarnings  = $gcWarnings
                    GcRecommend = $gcRecommend
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
        if ($tomcatInfo -and $tomcatInfo.GcWarnings)  { foreach ($w in $tomcatInfo.GcWarnings)  { $gcWarnings.Add($w)  } }
        if ($tomcatInfo -and $tomcatInfo.GcRecommend) { foreach ($r in $tomcatInfo.GcRecommend) { $gcRecommend.Add($r) } }
    }

    # ── JVM working set ────────────────────────────────────────────────────────
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

    # ── Overall status ─────────────────────────────────────────────────────────
    $checkTime     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $csvRows       = [System.Collections.Generic.List[PSCustomObject]]::new()
    $overallStatus = "OK"
    $allInformant  = [ordered]@{}

    if ($driveErrors.Count -gt 0)   { $overallStatus = "CRITICAL" }
    if ($memPct -ge 90)             { $overallStatus = "CRITICAL" }
    if ($cpuAvg -ge 90)             { if ($overallStatus -ne "CRITICAL") { $overallStatus = "WARN" } }
    if ($memPct -ge 75)             { if ($overallStatus -eq "OK") { $overallStatus = "WARN" } }
    if ($driveWarnings.Count -gt 0) { if ($overallStatus -eq "OK") { $overallStatus = "WARN" } }
    if ($recentTag -ne "")          { if ($overallStatus -eq "OK") { $overallStatus = "WARN" } }

    # ── Console output header ──────────────────────────────────────────────────
    $out = [System.Collections.Generic.List[string]]::new()
    $out.Add(""); $out.Add("========================================")
    $out.Add("Zone     : $GroupName"); $out.Add("Server   : $ComputerName")
    $out.Add("  Server Uptime: $uptimeStr$recentTag")
    $out.Add("  Memory       : $(Get-VisualBar -Pct $memPct) $memPct% used  ($usedMemGB GB / $totalMemGB GB)  Free: $freeMemGB GB$(Get-ThresholdTag -Pct $memPct)")
    $out.Add("  CPU          : $(Get-VisualBar -Pct $cpuAvg) $cpuAvg%$(Get-ThresholdTag -Pct $cpuAvg)")
    $out.Add("  Drives:")
    foreach ($dline in ($driveSummary -split "`n")) { $out.Add($dline) }
    if ($driveErrors.Count   -gt 0) { $out.Add("  [ERROR] Drive critical: " + ($driveErrors   -join "; ")) }
    if ($driveWarnings.Count -gt 0) { $out.Add("  [WARN] Drive warning: "  + ($driveWarnings  -join "; ")) }
    $out.Add("========================================")

    # ── Tomcat ─────────────────────────────────────────────────────────────────
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
            DateTime      = $checkTime;       Zone          = $GroupName
            Server        = $ComputerName;    ServiceType   = "Tomcat"
            ServiceName   = $tomcatSvc.Name;  DisplayName   = $tomcatSvc.DisplayName
            Description   = "";               Status        = $tomcatSvc.State
            Version       = $tomcatVersion;   CsVersion     = ""
            JrePath       = $jrePath;         HeapInitMB    = $heapInitMB;  HeapMaxMB = $heapMaxMB
            GcCollector   = $gcCollector
            GcWarnings    = ($gcWarnings  -join " | ")
            GcRecommend   = ($gcRecommend -join " | ")
            RunAs         = $tomcatSvc.StartName; ServiceUptime = $tUp
            RestartConfig = $tRestart;        AutoRestarts  = $tRestartCount
            WorkingSetMB  = $jvmHeapCsvStr;   ServerUptime  = $uptimeStr
            RecentReboot  = ($recentTag -ne ""); CpuPct      = $cpuAvg
            MemPct        = $memPct;          MemUsedGB     = $usedMemGB
            MemTotalGB    = $totalMemGB;       MemFreeGB    = $freeMemGB
            DrivesSummary = $drivesSummaryForCsv; OverallStatus = $overallStatus
        })
    } else {
        $out.Add("  NOT FOUND")
    }

    # ── Content Server(s) ──────────────────────────────────────────────────────
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

            # ── CS version lookup ──────────────────────────────────────────────
            $csVersion = Get-CsVersion -ServiceImagePath $cs.PathName -Computer $ComputerName -Cred $Credential

            $out.Add(""); $out.Add("  Instance:           $($cs.Name)")
            $out.Add("  Status:             $csState")
            $out.Add("  CS Version:         $csVersion")
            $out.Add("  Display Name:       $($cs.DisplayName)")
            $out.Add("  Description:        $($cs.Description)")
            $out.Add("  Run As:             $($cs.StartName)")
            $out.Add("  Service Uptime:     $csUp")
            $out.Add("  Restart Config:     $csRestart")
            $out.Add("  Auto-Restarts(24h): $csRestartCount")

            $csInformant = @{}
            $csInformantBaseUrl = ""
            if ($cs.State -eq "Running") {
                $pingBase   = "http://$ComputerName/$($cs.Name)/cs?func=informant.ping"
                $csInformantBaseUrl = $pingBase
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
                            Status = "ERROR"; Detail = $ir.Error; Ms = $ir.Ms; Slow = ($ir.Ms -ge $InformantWarnMs)
                            Url = "$pingBase&component=$comp"
                        }
                    } else {
                        $tag    = if ($ir.Content -match "=\s*success") { "SUCCESS" }
                                  elseif ($ir.Content -match "=\s*failure") { "FAILURE" }
                                  else { "OTHER" }
                        $detail = if ($tag -eq "OTHER") { $ir.Content } else { "" }
                        if ($tag -eq "FAILURE") { $overallStatus = "CRITICAL" }
                        $out.Add("    $comp : [$tag] $msLabel$slowTag")
                        $csInformant[$comp] = [PSCustomObject]@{
                            Status = $tag; Detail = $detail; Ms = $ir.Ms; Slow = ($ir.Ms -ge $InformantWarnMs)
                            Url = "$pingBase&component=$comp"
                        }
                    }
                }
                $out.Add(""); $out.Add("  --- System Resources ---")
                $out.Add("  CPU Usage : $(Get-VisualBar -Pct $cpuAvg) $cpuAvg%$(Get-ThresholdTag -Pct $cpuAvg)")
            } else {
                $out.Add("  [INFO] Skipped Informant checks - service is not running.")
            }

            $allInformant[$cs.Name] = $csInformant

            $csvRows.Add([PSCustomObject]@{
                DateTime      = $checkTime;    Zone          = $GroupName
                Server        = $ComputerName; ServiceType   = "ContentServer"
                ServiceName   = $cs.Name;      DisplayName   = $cs.DisplayName
                Description   = $cs.Description; Status      = $cs.State
                Version       = "";            CsVersion     = $csVersion
                JrePath       = ""; HeapInitMB = $null; HeapMaxMB = $null
                GcCollector   = ""; GcWarnings = ""; GcRecommend = ""
                RunAs         = $cs.StartName; ServiceUptime = $csUp
                RestartConfig = $csRestart;    AutoRestarts  = $csRestartCount
                WorkingSetMB  = "N/A";         ServerUptime  = $uptimeStr
                RecentReboot  = ($recentTag -ne ""); CpuPct  = $cpuAvg
                MemPct        = $memPct;       MemUsedGB     = $usedMemGB
                MemTotalGB    = $totalMemGB;    MemFreeGB    = $freeMemGB
                DrivesSummary = $drivesSummaryForCsv; OverallStatus = $overallStatus
            })
        }
    } else {
        $out.Add("  NOT FOUND")
    }

    # ── Content Server Admin ───────────────────────────────────────────────────
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
            DateTime      = $checkTime;     Zone          = $GroupName
            Server        = $ComputerName;  ServiceType   = "ContentServerAdmin"
            ServiceName   = $csAdmin.Name;  DisplayName   = $csAdmin.DisplayName
            Description   = $csAdmin.Description; Status = $csAdmin.State
            Version       = "";             CsVersion     = ""
            JrePath       = ""; HeapInitMB = $null; HeapMaxMB = $null
            GcCollector   = ""; GcWarnings = ""; GcRecommend = ""
            RunAs         = $csAdmin.StartName; ServiceUptime = $caUp
            RestartConfig = $caRestart;     AutoRestarts  = $caRestartCount
            WorkingSetMB  = "N/A";          ServerUptime  = $uptimeStr
            RecentReboot  = ($recentTag -ne ""); CpuPct   = $cpuAvg
            MemPct        = $memPct;        MemUsedGB     = $usedMemGB
            MemTotalGB    = $totalMemGB;     MemFreeGB    = $freeMemGB
            DrivesSummary = $drivesSummaryForCsv; OverallStatus = $overallStatus
        })
    } else {
        $out.Add("  NOT FOUND")
    }

    # ── Event log (console) ────────────────────────────────────────────────────
    if ($eventLines.Count -gt 0) {
        $out.Add(""); $out.Add("Recent Application Log Events (last 24h, Tomcat/CS related):")
        foreach ($line in $eventLines) { $out.Add("  $line") }
        if ($overallStatus -eq "OK") { $overallStatus = "WARN" }
    }

    Remove-CimSession $session -ErrorAction SilentlyContinue

    $instanceResults.Add([PSCustomObject]@{
        ComputerName  = $ComputerName;  GroupName     = $GroupName
        InstanceLabel = $ComputerName;  Output        = $out
        CsvRows       = $csvRows;       OverallStatus = $overallStatus
        TomcatVersion = $tomcatVersion; EventLines    = $eventLines
        DriveErrors   = $driveErrors;   DriveWarnings = $driveWarnings
        InformantResults = $allInformant
        GcCollector   = $gcCollector;   GcWarnings    = $gcWarnings
        GcRecommend   = $gcRecommend;   MemPct        = $memPct
        CpuAvg        = $cpuAvg;        MemUsedGB     = $usedMemGB
        MemTotalGB    = $totalMemGB;     MemFreeGB     = $freeMemGB
        DrivesSummary = $drivesSummaryForCsv; Uptime  = $uptimeStr
        JobLog        = $jobLog
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
            $key = [System.Console]::ReadKey($true)
            $useCreds = $key.KeyChar.ToString().ToLower()
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
Write-Log "Started: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Gray
Write-Log "Log file: $logFile" -Color Gray
Write-Log ""

# ── Start parallel jobs ────────────────────────────────────────────────────────
$jobs = [System.Collections.Generic.List[hashtable]]::new()
foreach ($group in $serverGroups.Keys) {
    foreach ($server in $serverGroups[$group]) {
        while ((Get-Job -State Running).Count -ge $MaxParallelJobs) { Start-Sleep -Milliseconds 200 }
        $j = Start-Job -ScriptBlock $checkServicesScript `
                 -ArgumentList $server, $group, $Credential, $webTimeoutSec, $InformantWarnMs,
                               $eventLogCount, $portCheckTimeout, ($AutoRestartStopped.IsPresent)
        $jobs.Add(@{ Job = $j; Server = $server; Group = $group })
        Write-Log "Queued: [$group] $server" -Color Gray
    }
}

Write-Log "Checking $serverCount server(s) in parallel (max $MaxParallelJobs concurrent)..." -Color Yellow

foreach ($entry in $jobs) {
    $finished = $entry.Job | Wait-Job -Timeout $jobTimeoutSec
    if (-not $finished) {
        Write-Log "TIMEOUT: [$($entry.Group)] $($entry.Server) - skipping." -Color Red
        Stop-Job  $entry.Job
        Remove-Job $entry.Job -Force
        $entry.Job = $null
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

# ── Delta detection ────────────────────────────────────────────────────────────
$prevData = @{}
$prevCsvs = Get-ChildItem -Path $PSScriptRoot -Filter "ServiceCheck_*.csv" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne (Split-Path $csvFile -Leaf) } |
            Sort-Object LastWriteTime -Descending
if ($prevCsvs) {
    $prevRows = Import-Csv -Path $prevCsvs[0].FullName -ErrorAction SilentlyContinue
    foreach ($row in $prevRows) { $prevData["$($row.Server)|$($row.ServiceName)"] = $row }
    Write-Log "Comparing against previous run: $($prevCsvs[0].Name)" -Color Gray
}

# ── Console output ─────────────────────────────────────────────────────────────
$prevGroup   = $null
$zoneSummary = [ordered]@{}
$allVersions = @{}

foreach ($result in ($results | Sort-Object GroupName, ComputerName)) {
    $grp = $result.GroupName
    if (-not $zoneSummary.Contains($grp)) { $zoneSummary[$grp] = @{ OK = 0; WARN = 0; DOWN = 0; CRITICAL = 0 } }
    $zoneSummary[$grp][$result.OverallStatus]++

    if ($result.TomcatVersion -and $result.TomcatVersion -notin @("N/A","Unknown","Unable to retrieve")) {
        if (-not $allVersions.Contains($grp)) { $allVersions[$grp] = @{} }
        $allVersions[$grp][$result.ComputerName] = $result.TomcatVersion
    }

    if ($grp -ne $prevGroup) {
        Write-Log ""; Write-Log "########################################" -Color Magenta
        Write-Log "# Zone: $grp" -Color Magenta
        Write-Log "########################################" -Color Magenta
        $prevGroup = $grp
    }

    $deltaDetails = [System.Collections.Generic.List[string]]::new()
    if ($result.CsvRows) {
        foreach ($row in $result.CsvRows) {
            $key  = "$($row.Server)|$($row.ServiceName)"
            $prev = $prevData[$key]
            if ($prev) {
                if ($prev.Status -ne $row.Status) { $deltaDetails.Add("$($row.ServiceName): Status $($prev.Status) -> $($row.Status)") }
                if ($prev.Version -and $row.Version -and $prev.Version -ne $row.Version) {
                    $deltaDetails.Add("$($row.ServiceName): Version $($prev.Version) -> $($row.Version)")
                }
            }
        }
    }
    $isClean = ($result.OverallStatus -eq "OK") -and ($deltaDetails.Count -eq 0)
    if ($QuietOK -and $isClean) { Write-Log "  $($result.ComputerName) : OK" -Color Green; continue }

    foreach ($line in $result.Output) {
        $color = "White"
        if     ($line -match "^={3,}|Server   :")                                                         { $color = "Cyan"    }
        elseif ($line -match "Zone     :")                                                                 { $color = "Magenta" }
        elseif ($line -match "Recent Reboot")                                                              { $color = "Yellow"  }
        elseif ($line -match "Tomcat Service:|Content Server Service|Informant Health|System Resources")  { $color = "Yellow"  }
        elseif ($line -match "^\[DRIVE_CRITICAL\] ")                                                      { $color = "Red"     }
        elseif ($line -match "\[RUNNING\]|\[SUCCESS\]")                                                   { $color = "Green"   }
        elseif ($line -match "\[STOPPED\]|ERROR:|NOT FOUND|\[FAILURE\]|\[ERROR\]|\[CRITICAL\]")          { $color = "Red"     }
        elseif ($line -match "\[WARN\]|\[OTHER\]|\[SLOW\]")                                               { $color = "Yellow"  }
        elseif ($line -match "\[AUTO-RESTART\]")                                                          { $color = "Cyan"    }
        elseif ($line -match "Working Set:|Auto-Restarts:|CPU|Memory|Drive")                              { $color = "Cyan"    }
        elseif ($line -match "Run As:|Restart Config:|Service Uptime:|CS Version:")                       { $color = "Cyan"    }
        elseif ($line -match "Description:|Display Name:")                                                { $color = "Gray"    }
        Write-Log $line -Color $color
    }

    if ($deltaDetails.Count -gt 0) {
        Write-Log "  >> Changes detected on $($result.ComputerName):" -Color Yellow
        foreach ($d in $deltaDetails) { Write-Log "     $d" -Color Yellow }
    }
}

# ── Zone rollup ────────────────────────────────────────────────────────────────
Write-Log ""; Write-Log "======== Zone Rollup ========" -Color Cyan
foreach ($grp in $zoneSummary.Keys) {
    $s   = $zoneSummary[$grp]
    $tot = $s.OK + $s.WARN + $s.DOWN + $s.CRITICAL
    $col = if ($s.DOWN -gt 0 -or $s.CRITICAL -gt 0) { "Red" } elseif ($s.WARN -gt 0) { "Yellow" } else { "Green" }
    Write-Log ("  {0,-40} : {1} OK, {2} WARN, {3} CRITICAL, {4} DOWN  (of {5})" -f
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

# ── CSV ────────────────────────────────────────────────────────────────────────
$allCsvRows = $results | ForEach-Object { $_.CsvRows } | Where-Object { $_ }
if ($allCsvRows) {
    $allCsvRows | Sort-Object Zone, Server, ServiceType |
        Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Log "CSV saved to   : $csvFile" -Color Green
} else {
    Write-Log "No CSV data to export." -Color Yellow
}

# ── HTML (tile-based, zone-separated) ─────────────────────────────────────────
$reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$totalOK    = ($results | Where-Object { $_.OverallStatus -eq "OK"       }).Count
$totalWarn  = ($results | Where-Object { $_.OverallStatus -eq "WARN"     }).Count
$totalCrit  = ($results | Where-Object { $_.OverallStatus -eq "CRITICAL" }).Count
$totalDown  = ($results | Where-Object { $_.OverallStatus -eq "DOWN"     }).Count
$totalAll   = $results.Count

$zonesHtml = ""
foreach ($group in $serverGroups.Keys) {
    $zoneResults = $results | Where-Object { $_.GroupName -eq $group } | Sort-Object ComputerName
    if (-not $zoneResults) { continue }

    $zOK   = ($zoneResults | Where-Object { $_.OverallStatus -eq "OK"       }).Count
    $zWarn = ($zoneResults | Where-Object { $_.OverallStatus -eq "WARN"     }).Count
    $zCrit = ($zoneResults | Where-Object { $_.OverallStatus -eq "CRITICAL" }).Count
    $zDown = ($zoneResults | Where-Object { $_.OverallStatus -eq "DOWN"     }).Count

    $zoneClass     = if ($zDown -gt 0 -or $zCrit -gt 0) { "zone-critical" } elseif ($zWarn -gt 0) { "zone-warn" } else { "zone-ok" }
    $zonePillsHtml = ""
    if ($zOK   -gt 0) { $zonePillsHtml += "<span class='zpill zpill-ok'>$zOK OK</span>" }
    if ($zWarn -gt 0) { $zonePillsHtml += "<span class='zpill zpill-warn'>$zWarn WARN</span>" }
    if ($zCrit -gt 0) { $zonePillsHtml += "<span class='zpill zpill-crit'>$zCrit CRITICAL</span>" }
    if ($zDown -gt 0) { $zonePillsHtml += "<span class='zpill zpill-down'>$zDown DOWN</span>" }

    $tilesHtml = ""
    foreach ($result in $zoneResults) {
        $sName     = HtmlEncode $result.ComputerName
        $status    = $result.OverallStatus
        $cardClass = switch ($status) { "OK"{"card-ok"} "WARN"{"card-warn"} "CRITICAL"{"card-crit"} default{"card-down"} }

        $statusBadge = switch ($status) {
            "OK"       { "<span class='badge badge-ok'><svg viewBox='0 0 12 12'><rect x='1' y='1' width='10' height='10' rx='2'/></svg>OK</span>" }
            "WARN"     { "<span class='badge badge-warn'><svg viewBox='0 0 12 12'><circle cx='6' cy='6' r='5'/></svg>WARN</span>" }
            "CRITICAL" { "<span class='badge badge-crit'><svg viewBox='0 0 12 14'><polygon points='6,1 11,13 1,13'/></svg>CRITICAL</span>" }
            default    { "<span class='badge badge-down'><svg viewBox='0 0 12 14'><polygon points='6,1 11,13 1,13'/></svg>DOWN</span>" }
        }

        $csRows     = @($result.CsvRows | Where-Object { $_.ServiceType -eq "ContentServer" })
        $tomcatRow  = $result.CsvRows | Where-Object { $_.ServiceType -eq "Tomcat" }             | Select-Object -First 1
        $csAdminRow = $result.CsvRows | Where-Object { $_.ServiceType -eq "ContentServerAdmin" } | Select-Object -First 1

        # Card header: "INST1, INST2 / hostname"
        $csInstanceNames = ($csRows | ForEach-Object { HtmlEncode $_.ServiceName }) -join ", "
        $instancePrefix  = if ($csInstanceNames) {
            "<span class='card-instances'>$csInstanceNames</span><span class='card-sep'> / </span>"
        } else { "" }

        # Metric bars
        $memPct     = $result.MemPct
        $memClass   = if ($memPct -ge 90) { "bar-crit" } elseif ($memPct -ge 75) { "bar-warn" } else { "bar-ok" }
        $memDisplay = "$memPct% ($($result.MemUsedGB)/$($result.MemTotalGB) GB)"
        $cpuPct     = $result.CpuAvg
        $cpuClass   = if ($cpuPct -ge 90) { "bar-crit" } elseif ($cpuPct -ge 75) { "bar-warn" } else { "bar-ok" }

        $driveBarsHtml = ""
        $firstRow = ($result.CsvRows | Select-Object -First 1)
        if ($firstRow -and $firstRow.DrivesSummary) {
            foreach ($driveEntry in ($firstRow.DrivesSummary -split " \| ")) {
                if ($driveEntry -match "^([A-Z]:) ([\d.]+)% \(([\d.]+)\/([\d.]+) GB\)") {
                    $dLetter = $Matches[1]; $dPct = [double]$Matches[2]
                    $dUsed = $Matches[3]; $dTotal = $Matches[4]
                    $dClass = if ($dPct -ge 90) { "bar-crit" } elseif ($dPct -ge 75) { "bar-warn" } else { "bar-ok" }
                    $driveBarsHtml += "<div class='metric-row'><span class='metric-label'>Disk $dLetter</span><div class='bar-wrap'><div class='bar $dClass' style='width:$dPct%'></div></div><span class='metric-val $dClass'>$dPct% ($dUsed/$dTotal GB)</span></div>"
                }
            }
        }

        # Services
        $servicesHtml = ""

        if ($tomcatRow) {
            $tClass  = if ($tomcatRow.Status -eq "Running") { "svc-ok" } else { "svc-down" }
            $tIcon   = if ($tomcatRow.Status -eq "Running") { "&#9632;" } else { "&#9650;" }
            $tVer    = if ($tomcatRow.Version -and $tomcatRow.Version -notin @("N/A","Unknown","Unable to retrieve","")) {
                           "<span class='svc-ver'>v$($tomcatRow.Version)</span>" } else { "" }
            $tUptime = if ($tomcatRow.ServiceUptime -and $tomcatRow.ServiceUptime -ne "N/A") {
                           "<div class='svc-uptime-row'><span class='svc-uptime'>$(HtmlEncode $tomcatRow.ServiceUptime)</span></div>" } else { "" }
            $servicesHtml += "<div class='svc-row'><span class='svc-icon $tClass'>$tIcon</span><span class='svc-name'>Tomcat</span>$tVer<span class='svc-status $tClass'>$(HtmlEncode $tomcatRow.Status)</span></div>$tUptime"
        }

        foreach ($csRow in $csRows) {
            $cClass  = if ($csRow.Status -eq "Running") { "svc-ok" } else { "svc-down" }
            $cIcon   = if ($csRow.Status -eq "Running") { "&#9632;" } else { "&#9650;" }
            $csVer   = if ($csRow.PSObject.Properties['CsVersion'] -and $csRow.CsVersion -and $csRow.CsVersion -ne "N/A") {
                           "<span class='svc-ver'>v$(HtmlEncode $csRow.CsVersion)</span>" } else { "" }
            $csUptime = if ($csRow.ServiceUptime -and $csRow.ServiceUptime -ne "N/A") {
                            "<div class='svc-uptime-row'><span class='svc-uptime'>$(HtmlEncode $csRow.ServiceUptime)</span></div>" } else { "" }
            $servicesHtml += "<div class='svc-row'><span class='svc-icon $cClass'>$cIcon</span><span class='svc-name'>$(HtmlEncode $csRow.ServiceName)</span>$csVer<span class='svc-status $cClass'>$(HtmlEncode $csRow.Status)</span></div>$csUptime"

            $csInformant = $result.InformantResults[$csRow.ServiceName]
            if ($csInformant -and $csInformant.Count -gt 0) {
                $informantHtml = "<div class='informant-grid'>"
                foreach ($comp in $csInformant.Keys) {
                    $ir = $csInformant[$comp]
                    $iClass = switch ($ir.Status) { "SUCCESS"{"inf-ok"} "FAILURE"{"inf-fail"} "ERROR"{"inf-fail"} default{"inf-warn"} }
                    $iIcon  = switch ($ir.Status) { "SUCCESS"{"&#9632;"} "FAILURE"{"&#9650;"} "ERROR"{"&#9650;"} default{"&#9679;"} }
                    $slowTag = if ($ir.Slow) { " <span class='inf-slow'>SLOW</span>" } else { "" }
                    $iUrl    = if ($ir.PSObject.Properties['Url'] -and $ir.Url) { HtmlEncode $ir.Url } else { "" }
                    $titleAttr = "$(HtmlEncode $ir.Status) - $($ir.Ms)ms$(if($ir.Detail){" — $(HtmlEncode $ir.Detail)"})"
                    if ($iUrl) {
                        $informantHtml += "<a class='inf-cell $iClass' href='$iUrl' target='_blank' rel='noopener' title='$titleAttr (click to open)'>$iIcon $(HtmlEncode $comp)$slowTag</a>"
                    } else {
                        $informantHtml += "<div class='inf-cell $iClass' title='$titleAttr'>$iIcon $(HtmlEncode $comp)$slowTag</div>"
                    }
                }
                $informantHtml += "</div>"
                $servicesHtml += "<div class='informant-wrap'><div class='informant-label'>Informant</div>$informantHtml</div>"
            }
        }

        if ($csAdminRow) {
            $aClass  = if ($csAdminRow.Status -eq "Running") { "svc-ok" } else { "svc-down" }
            $aIcon   = if ($csAdminRow.Status -eq "Running") { "&#9632;" } else { "&#9650;" }
            $aUptime = if ($csAdminRow.ServiceUptime -and $csAdminRow.ServiceUptime -ne "N/A") {
                           "<div class='svc-uptime-row'><span class='svc-uptime'>$(HtmlEncode $csAdminRow.ServiceUptime)</span></div>" } else { "" }
            $servicesHtml += "<div class='svc-row'><span class='svc-icon $aClass'>$aIcon</span><span class='svc-name'>CS Admin</span><span class='svc-status $aClass'>$(HtmlEncode $csAdminRow.Status)</span></div>$aUptime"
        }

        # Alerts
        $alertsHtml = ""
        foreach ($de in $result.DriveErrors)   { $alertsHtml += "<div class='alert alert-crit'>&#9650; Drive: $(HtmlEncode $de)</div>" }
        foreach ($dw in $result.DriveWarnings) { $alertsHtml += "<div class='alert alert-warn'>&#9679; Drive: $(HtmlEncode $dw)</div>" }
        foreach ($w  in $result.GcWarnings)    { $alertsHtml += "<div class='alert alert-warn'>&#9679; GC: $(HtmlEncode $w)</div>" }
        foreach ($ev in $result.EventLines)    { $alertsHtml += "<div class='alert alert-warn'>&#9679; $(HtmlEncode $ev)</div>" }

        $serverUptimeHtml = if ($result.Uptime -and $result.Uptime -ne "N/A") {
            "<div class='srv-uptime'>Server up: $(HtmlEncode $result.Uptime)</div>" } else { "" }

        # RDP link: mstsc URI — clicking launches Remote Desktop to this server
        $rdpLink = "javascript:void(window.open('','_self').location='mstsc://' + encodeURIComponent('$($result.ComputerName)'))"
        # Cleaner: use a data attribute and handle via JS to avoid PS string quoting issues
        $rdpHostname = HtmlEncode $result.ComputerName

        $tilesHtml += @"
<div class='server-card $cardClass'>
  <div class='card-header'>
    <div class='card-title'>$instancePrefix<a class='card-hostname rdp-link' href='#' data-rdp='$rdpHostname' onclick="launchRdp('$rdpHostname');return false;" title='Click to copy RDP command for $rdpHostname'>$sName</a>$statusBadge</div>
    $serverUptimeHtml
  </div>
  <div class='card-body'>
    <div class='metrics'>
      <div class='metric-row'><span class='metric-label'>CPU</span><div class='bar-wrap'><div class='bar $cpuClass' style='width:$cpuPct%'></div></div><span class='metric-val $cpuClass'>$cpuPct%</span></div>
      <div class='metric-row'><span class='metric-label'>Memory</span><div class='bar-wrap'><div class='bar $memClass' style='width:$([math]::Min($memPct,100))%'></div></div><span class='metric-val $memClass'>$memDisplay</span></div>
      $driveBarsHtml
    </div>
    <div class='services'>$servicesHtml</div>
    $(if ($alertsHtml) { "<div class='alerts'>$alertsHtml</div>" })
  </div>
</div>
"@
    }

    $zonesHtml += @"
<section class='zone-section $zoneClass'>
  <div class='zone-header'><div class='zone-title-row'><span class='zone-name'>$(HtmlEncode $group)</span><div class='zone-pills'>$zonePillsHtml</div></div></div>
  <div class='zone-tiles'>$tilesHtml</div>
</section>
"@
}

$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Service Check Report - $reportDate</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0b0e14;--bg2:#111520;--bg3:#171d2d;
  --border:#1e2535;--border2:#2a3350;
  --text:#c8d0e0;--text-dim:#6b7a99;--text-bright:#e8edf8;
  --ok:#22c55e;--ok-dim:#14532d;--ok-bg:#0d2118;
  --warn:#f59e0b;--warn-dim:#78350f;--warn-bg:#1c1408;
  --crit:#f97316;--crit-dim:#7c2d12;--crit-bg:#1c0f06;
  --down:#ef4444;--down-dim:#7f1d1d;--down-bg:#1a0909;
  --font-mono:'JetBrains Mono','Fira Code','Consolas',monospace;
  --font-ui:'IBM Plex Sans','Segoe UI',system-ui,sans-serif;
}
body{font-family:var(--font-ui);background:var(--bg);color:var(--text);min-height:100vh;padding:0 0 60px;font-size:13px;line-height:1.5}
.page-header{background:linear-gradient(180deg,#131929 0%,#0b0e14 100%);border-bottom:1px solid var(--border2);padding:24px 32px 20px;display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.header-logo{width:44px;height:44px;background:linear-gradient(135deg,#1e40af,#3b82f6);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:22px;flex-shrink:0;box-shadow:0 0 20px rgba(59,130,246,.35)}
.header-info h1{font-family:var(--font-mono);font-size:18px;font-weight:700;color:var(--text-bright);letter-spacing:-.5px}
.header-info .sub{font-size:11px;color:var(--text-dim);margin-top:3px;font-family:var(--font-mono)}
.header-stats{margin-left:auto;display:flex;gap:10px;flex-wrap:wrap}
.hstat{background:var(--bg3);border:1px solid var(--border2);border-radius:8px;padding:8px 16px;text-align:center;min-width:72px}
.hstat .n{font-size:22px;font-weight:700;font-family:var(--font-mono);line-height:1}
.hstat .l{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--text-dim);margin-top:2px}
.hstat.s-ok .n{color:var(--ok)}.hstat.s-warn .n{color:var(--warn)}.hstat.s-crit .n{color:var(--crit)}.hstat.s-down .n{color:var(--down)}.hstat.s-all .n{color:#60a5fa}
.a11y-bar{background:var(--bg2);border-bottom:1px solid var(--border);padding:6px 32px;display:flex;align-items:center;gap:12px}
.a11y-bar label{font-size:11px;color:var(--text-dim);cursor:pointer;display:flex;align-items:center;gap:6px}
.a11y-bar input[type=checkbox]{accent-color:#3b82f6;width:14px;height:14px;cursor:pointer}
/* ── Monochromatic mode: strip all color, use brightness/pattern only ── */
body.mono{filter:grayscale(1) contrast(1.1)}
body.mono .zone-section,
body.mono .server-card{border-color:#555!important;background:#111!important}
body.mono .zone-header{background:#1a1a1a!important}
body.mono .card-header{background:#1c1c1c!important}
body.mono .hstat.s-ok .n,
body.mono .hstat.s-warn .n,
body.mono .hstat.s-crit .n,
body.mono .hstat.s-down .n{color:#e0e0e0}
body.mono .svc-ok,body.mono .zone-ok{color:#ddd!important}
body.mono .svc-down,body.mono .svc-warn,
body.mono .zone-down,body.mono .zone-warn{color:#888!important}
body.mono .bar{background:#666!important}
body.mono .bar-ok{background:#aaa!important}
body.mono .bar-warn{background:#777!important;border:1px solid #999}
body.mono .bar-crit{background:#444!important;border:2px dashed #bbb}
body.mono .inf-ok{background:#2a2a2a!important;color:#ccc!important;border-color:#555!important}
body.mono .inf-fail{background:#1a1a1a!important;color:#fff!important;border:2px solid #bbb!important;font-weight:700}
body.mono .inf-warn{background:#222!important;color:#aaa!important;border-color:#666!important}
body.mono .status-badge-ok{background:#2a2a2a!important;color:#ccc!important;border-color:#555!important}
body.mono .status-badge-warn{background:#222!important;color:#bbb!important;border:1px dashed #777!important}
body.mono .status-badge-crit,
body.mono .status-badge-down{background:#111!important;color:#fff!important;border:2px solid #ddd!important;font-weight:700}
body.mono .alert-crit{background:#1a1a1a!important;border-left:4px solid #fff!important;color:#fff!important}
body.mono .alert-warn{background:#1a1a1a!important;border-left:4px solid #999!important;color:#ccc!important}
body.mono .zone-pill-ok{background:#333!important;color:#bbb!important}
body.mono .zone-pill-warn{background:#222!important;color:#aaa!important;border:1px dashed #777!important}
body.mono .zone-pill-crit,
body.mono .zone-pill-down{background:#111!important;color:#fff!important;border:1px solid #ddd!important;font-weight:700}
.legend{display:flex;gap:14px;margin-left:auto;flex-wrap:wrap}
.leg{display:flex;align-items:center;gap:5px;font-size:10px;color:var(--text-dim)}
.leg svg{width:10px;height:12px;flex-shrink:0}
.zone-section{margin:28px 28px 0;border-radius:14px;overflow:hidden}
.zone-section+.zone-section{margin-top:22px}
.zone-header{padding:14px 20px 12px;display:flex;align-items:center}
.zone-title-row{display:flex;align-items:center;gap:12px;width:100%;flex-wrap:wrap}
.zone-name{font-family:var(--font-mono);font-size:13px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--text-bright)}
.zone-pills{display:flex;gap:6px;flex-wrap:wrap}
.zpill{font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;font-family:var(--font-mono);letter-spacing:.04em}
.zpill-ok{background:var(--ok-dim);color:var(--ok);border:1px solid var(--ok-dim)}
.zpill-warn{background:var(--warn-dim);color:var(--warn);border:1px solid var(--warn-dim)}
.zpill-crit{background:var(--crit-dim);color:var(--crit);border:1px solid var(--crit-dim)}
.zpill-down{background:var(--down-dim);color:var(--down);border:1px solid var(--down-dim)}
.zone-ok{background:var(--bg2);border:1px solid var(--ok-dim)}
.zone-warn{background:var(--bg2);border:1px solid var(--warn-dim)}
.zone-critical{background:var(--bg2);border:1px solid var(--crit-dim)}
.zone-ok .zone-header{background:linear-gradient(90deg,rgba(34,197,94,.08),transparent)}
.zone-warn .zone-header{background:linear-gradient(90deg,rgba(245,158,11,.08),transparent)}
.zone-critical .zone-header{background:linear-gradient(90deg,rgba(249,115,22,.08),transparent)}
.zone-tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px;padding:4px 16px 18px}
.server-card{background:var(--bg3);border-radius:10px;border:1px solid var(--border2);overflow:hidden;transition:box-shadow .2s,transform .15s;display:flex;flex-direction:column}
.server-card:hover{transform:translateY(-2px);box-shadow:0 8px 28px rgba(0,0,0,.4)}
.card-ok{border-top:3px solid var(--ok)}.card-warn{border-top:3px solid var(--warn)}.card-crit{border-top:3px solid var(--crit)}.card-down{border-top:3px solid var(--down)}
.card-header{padding:11px 14px 8px;border-bottom:1px solid var(--border);display:flex;flex-direction:column;gap:3px}
.card-title{display:flex;align-items:center;gap:6px;flex-wrap:wrap;min-width:0}
.card-instances{font-family:var(--font-mono);font-size:11px;font-weight:700;color:#60a5fa;flex-shrink:0;white-space:nowrap}
.card-sep{color:var(--text-dim);font-size:11px;flex-shrink:0}
.card-hostname{font-family:var(--font-mono);font-size:12px;font-weight:600;color:var(--text-bright);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
a.rdp-link{text-decoration:none;cursor:pointer;border-bottom:1px dashed rgba(200,208,224,.35);transition:color .15s,border-color .15s}
a.rdp-link:hover{color:#93c5fd;border-bottom-color:#93c5fd}
.badge{display:inline-flex;align-items:center;gap:4px;font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;font-family:var(--font-mono);letter-spacing:.05em;flex-shrink:0}
.badge svg{width:9px;height:11px;flex-shrink:0}
.badge-ok{background:var(--ok-bg);color:var(--ok);border:1px solid var(--ok-dim)}
.badge-warn{background:var(--warn-bg);color:var(--warn);border:1px solid var(--warn-dim)}
.badge-crit{background:var(--crit-bg);color:var(--crit);border:1px solid var(--crit-dim)}
.badge-down{background:var(--down-bg);color:var(--down);border:1px solid var(--down-dim)}
.badge-ok svg{fill:var(--ok)}.badge-warn svg{fill:var(--warn)}.badge-crit svg{fill:var(--crit)}.badge-down svg{fill:var(--down)}
.srv-uptime{font-size:10px;color:var(--text-dim);font-family:var(--font-mono)}
.card-body{padding:12px 14px;display:flex;flex-direction:column;gap:12px;flex:1}
.metrics{display:flex;flex-direction:column;gap:6px}
.metric-row{display:flex;align-items:center;gap:7px}
.metric-label{font-size:10px;font-family:var(--font-mono);color:var(--text-dim);width:52px;flex-shrink:0;text-align:right}
.bar-wrap{flex:1;height:6px;background:var(--border2);border-radius:3px;overflow:hidden;min-width:0}
.bar{height:100%;border-radius:3px;transition:width .4s ease}
.bar-ok{background:var(--ok)}.bar-warn{background:var(--warn)}.bar-crit{background:var(--crit)}
.metric-val{font-size:10px;font-family:var(--font-mono);width:114px;flex-shrink:0}
.metric-val.bar-ok{color:var(--ok)}.metric-val.bar-warn{color:var(--warn)}.metric-val.bar-crit{color:var(--crit)}
.services{display:flex;flex-direction:column;gap:2px;border-top:1px solid var(--border);padding-top:10px}
.svc-row{display:flex;align-items:center;gap:6px}
.svc-icon{font-size:9px;width:14px;text-align:center;flex-shrink:0}
.svc-name{flex:1;font-size:11px;font-family:var(--font-mono);color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.svc-ver{font-size:10px;color:var(--text-dim);margin-right:4px;flex-shrink:0}
.svc-status{font-size:10px;font-weight:700;font-family:var(--font-mono);flex-shrink:0}
.svc-ok{color:var(--ok)}.svc-down{color:var(--down)}
.svc-uptime-row{padding-left:20px;margin-bottom:3px}
.svc-uptime{font-size:9px;color:var(--text-dim);font-family:var(--font-mono)}
.informant-wrap{margin-left:20px;margin-top:3px;margin-bottom:4px}
.informant-label{font-size:9px;text-transform:uppercase;letter-spacing:.08em;color:var(--text-dim);margin-bottom:4px;font-family:var(--font-mono)}
.informant-grid{display:flex;flex-wrap:wrap;gap:4px}
.inf-cell{font-size:9px;font-family:var(--font-mono);padding:2px 6px;border-radius:3px;cursor:default;display:flex;align-items:center;gap:3px;border:1px solid transparent;text-decoration:none}
a.inf-cell{cursor:pointer}
a.inf-cell:hover{filter:brightness(1.3);border-color:rgba(255,255,255,.25)}
.inf-ok{background:var(--ok-bg);color:var(--ok);border-color:rgba(34,197,94,.25)}
.inf-fail{background:var(--crit-bg);color:var(--crit);border-color:rgba(249,115,22,.25)}
.inf-warn{background:var(--warn-bg);color:var(--warn);border-color:rgba(245,158,11,.25)}
.inf-slow{background:rgba(245,158,11,.2);color:var(--warn);border-radius:2px;padding:0 3px;font-size:8px;margin-left:2px}
.alerts{display:flex;flex-direction:column;gap:4px;border-top:1px solid var(--border);padding-top:10px}
.alert{font-size:10px;font-family:var(--font-mono);padding:4px 8px;border-radius:4px;line-height:1.4;word-break:break-word}
.alert-crit{background:var(--crit-bg);color:var(--crit);border-left:3px solid var(--crit)}
.alert-warn{background:var(--warn-bg);color:var(--warn);border-left:3px solid var(--warn)}
@media(max-width:700px){.zone-tiles{grid-template-columns:1fr}.page-header{padding:16px}.zone-section{margin:16px 12px 0}}
</style>
</head>
<body>
<header class='page-header'>
  <div class='header-logo'>&#128736;</div>
  <div class='header-info'>
    <h1>SERVICE CHECK REPORT</h1>
    <div class='sub'>Generated: $reportDate</div>
  </div>
  <div class='header-stats'>
    <div class='hstat s-all'><div class='n'>$totalAll</div><div class='l'>Total</div></div>
    <div class='hstat s-ok'><div class='n'>$totalOK</div><div class='l'>OK</div></div>
    <div class='hstat s-warn'><div class='n'>$totalWarn</div><div class='l'>Warn</div></div>
    <div class='hstat s-crit'><div class='n'>$totalCrit</div><div class='l'>Critical</div></div>
    <div class='hstat s-down'><div class='n'>$totalDown</div><div class='l'>Down</div></div>
  </div>
</header>
<div class='a11y-bar'>
  <label><input type='checkbox' id='a11yToggle' onchange="document.body.classList.toggle('mono',this.checked)">Monochromatic mode</label>
  <div class='legend'>
    <span class='leg'><svg viewBox='0 0 10 10' fill='currentColor'><rect x='1' y='1' width='8' height='8' rx='1.5'/></svg>OK</span>
    <span class='leg'><svg viewBox='0 0 10 10' fill='currentColor'><circle cx='5' cy='5' r='4'/></svg>Warning</span>
    <span class='leg'><svg viewBox='0 0 10 12' fill='currentColor'><polygon points='5,1 9,11 1,11'/></svg>Critical/Down</span>
  </div>
</div>
$zonesHtml
<script>
// ── RDP launcher ──────────────────────────────────────────────────────────────
// file:// pages cannot use navigator.clipboard (requires HTTPS/localhost).
// Instead we show a small modal with the command pre-selected — user hits
// Ctrl+C (auto-copies on most browsers even from file://) then Enter to close,
// then Win+R, Ctrl+V, Enter to launch RDP.
function launchRdp(hostname) {
    var cmd = "mstsc /v:" + hostname;

    // Remove any existing modal
    var old = document.getElementById("rdp-modal");
    if (old) old.parentNode.removeChild(old);

    // Build modal overlay
    var overlay = document.createElement("div");
    overlay.id = "rdp-modal";
    overlay.style.cssText = [
        "position:fixed","top:0","left:0","width:100%","height:100%",
        "background:rgba(0,0,0,.72)","display:flex","align-items:center",
        "justify-content:center","z-index:9999","font-family:'IBM Plex Sans',sans-serif"
    ].join(";");

    overlay.innerHTML = [
        "<div style='background:#1a2035;border:1px solid #2a3a5a;border-radius:12px;",
        "padding:24px 28px;min-width:380px;max-width:90vw;box-shadow:0 8px 40px rgba(0,0,0,.6)'>",
        "<div style='font-size:12px;color:#6b7a99;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px'>",
        "RDP Command &mdash; " + hostname + "</div>",
        "<div style='font-size:11px;color:#8a9abf;margin-bottom:12px'>",
        "Press <kbd style='background:#0d1525;border:1px solid #2a3a5a;border-radius:4px;",
        "padding:1px 6px;font-size:11px'>Ctrl+A</kbd> then ",
        "<kbd style='background:#0d1525;border:1px solid #2a3a5a;border-radius:4px;",
        "padding:1px 6px;font-size:11px'>Ctrl+C</kbd> to copy, ",
        "then paste into <strong style='color:#c8d0e0'>Win+R</strong></div>",
        "<input id='rdp-cmd-input' type='text' value='" + cmd + "'",
        " readonly style='width:100%;background:#0d1525;border:1px solid #2a3a5a;",
        "border-radius:6px;padding:10px 12px;color:#93c5fd;font-family:'Consolas',monospace;",
        "font-size:14px;font-weight:600;letter-spacing:.02em;outline:none;cursor:text'>",
        "<div style='display:flex;gap:10px;margin-top:16px;justify-content:flex-end'>",
        "<button onclick='rdpSelectAll()' style='background:#1e3a6e;border:1px solid #2a5abf;",
        "color:#93c5fd;border-radius:6px;padding:7px 16px;font-size:12px;cursor:pointer'>",
        "Select All</button>",
        "<button onclick='rdpClose()' style='background:#2a3350;border:1px solid #3a4560;",
        "color:#c8d0e0;border-radius:6px;padding:7px 16px;font-size:12px;cursor:pointer'>",
        "Close</button></div></div>"
    ].join("");

    document.body.appendChild(overlay);

    // Auto-select the input so Ctrl+C works immediately
    setTimeout(function() {
        var inp = document.getElementById("rdp-cmd-input");
        if (inp) { inp.focus(); inp.select(); }
    }, 50);

    // Close on overlay click (outside the box)
    overlay.addEventListener("click", function(e) {
        if (e.target === overlay) rdpClose();
    });
    // Close on Escape
    document.addEventListener("keydown", rdpEscHandler);
}
function rdpSelectAll() {
    var inp = document.getElementById("rdp-cmd-input");
    if (inp) { inp.focus(); inp.select(); }
}
function rdpClose() {
    var m = document.getElementById("rdp-modal");
    if (m) m.parentNode.removeChild(m);
    document.removeEventListener("keydown", rdpEscHandler);
}
function rdpEscHandler(e) {
    if (e.key === "Escape") rdpClose();
}
</script>
</body>
</html>
"@

$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($htmlFile, $htmlContent, $utf8Bom)
Write-Log "HTML saved to  : $htmlFile" -Color Green

# ── Alerts ─────────────────────────────────────────────────────────────────────
$issueRows = $allCsvRows | Where-Object { $_.OverallStatus -in @("DOWN","CRITICAL") }
if ($issueRows) {
    $bodyLines = @("Service Check Alert - $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))", "")
    foreach ($r in $issueRows) {
        $bodyLines += "[$($r.OverallStatus)] $($r.Zone) / $($r.Server) - $($r.ServiceType) ($($r.ServiceName)): $($r.Status)"
    }
    $bodyText = $bodyLines -join "`n"
    try {
        Send-MailMessage -SmtpServer $SmtpServer -From $EmailFrom -To $EmailTo `
            -Subject "Service Check Alert: $($issueRows.Count) issue(s) detected" `
            -Body $bodyText -ErrorAction Stop
        Write-Log "Alert email sent to $EmailTo" -Color Green
    } catch { Write-Log "Failed to send alert email: $_" -Color Red }
    if ($TeamsWebhookUrl) {
        Send-TeamsAlert -WebhookUrl $TeamsWebhookUrl `
            -Title "Service Check Alert: $($issueRows.Count) issue(s)" -Body $bodyText
        Write-Log "Teams alert sent." -Color Green
    }
}

# ── Footer ─────────────────────────────────────────────────────────────────────
$endTime = Get-Date
$dur     = $endTime - $startTime
Write-Log ""
Write-Log "========================================" -Color Cyan
Write-Log "Completed: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Cyan
Write-Log "Duration:  $($dur.ToString('mm\:ss'))" -Color Cyan
Write-Log "========================================" -Color Cyan
Write-Log "Log  : $logFile" -Color Green
Write-Log "CSV  : $csvFile" -Color Green
Write-Log "HTML : $htmlFile" -Color Green
#endregion

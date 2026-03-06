#Requires -Version 5.1
# Remote Service Status Checker (Parallel with Logging)
# Checks Tomcat, Content Server, and Content Server Admin on remote Windows servers
# v3.2 -- refined HTML UI: no red, monochrome toggle, critical inline, collapsed zones/informant

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  DEVELOPER NOTES — READ BEFORE EDITING                                      ║
# ╠══════════════════════════════════════════════════════════════════════════════╣
# ║  HERE-STRING RULES (PowerShell is strict — violations cause parse errors)   ║
# ║                                                                              ║
# ║  1. The OPENING delimiter  @"  must be the LAST thing on its line.           ║
# ║       OK  →  $x = @"                                                        ║
# ║       BAD →  $x = @"  # comment          (nothing after @")                 ║
# ║                                                                              ║
# ║  2. The CLOSING delimiter  "@  must be:                                      ║
# ║       a) On its OWN line                                                     ║
# ║       b) At COLUMN 1 — NO leading spaces or tabs                            ║
# ║       c) Nothing else on that line (no comments, no semicolons)             ║
# ║                                                                              ║
# ║       OK  →  "@           (first character on the line)                     ║
# ║       BAD →      "@       (indented — THIS was the original bug)            ║
# ║       BAD →  "@ # end     (trailing comment)                                ║
# ║                                                                              ║
# ║  3. AVOID complex subexpressions inside here-strings.                        ║
# ║     Pre-compute values into variables BEFORE the @" block, then             ║
# ║     reference the variable inside it.                                        ║
# ║       BAD inside @" ... "@  →  $(if ($x) { 'On' } else { 'Off' })          ║
# ║       OK  →  $autoRestartLabel = if ($AutoRestartStopped) {'On'} else {'Off'}║
# ║              then use  $autoRestartLabel  inside the here-string             ║
# ║                                                                              ║
# ║  4. When editing the HTML/CSS/JS section near the bottom of this file,      ║
# ║     make sure you do NOT accidentally indent the closing  "@  line.          ║
# ║     Most editors auto-indent — double-check after pasting or reformatting.  ║
# ║                                                                              ║
# ║  5. Save this file as UTF-8 (with or without BOM). Mixed CRLF/LF line       ║
# ║     endings can cause here-string parse failures on some PS versions.       ║
# ║     Normalize with:  (Get-Content .\status.ps1 -Raw) -replace "`r`n","`n"  ║
# ║                       | Set-Content .\status.ps1 -NoNewline                 ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

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
    Write-Host "ERROR: Server config file not found: $configFile" -ForegroundColor Yellow
    Write-Host "Create a servers.txt file in the same directory as this script," -ForegroundColor White
    Write-Host "with one server FQDN per line. Lines starting with # are comments." -ForegroundColor White
    Write-Host "Group servers with [ZoneName] section headers." -ForegroundColor White
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
    Write-Host "ERROR: No servers found in $configFile" -ForegroundColor Yellow
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
        Write-Log "Teams webhook failed: $_" -Color Yellow
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
    $jobLog = [System.Collections.Generic.List[string]]::new()
    $scHost = $ComputerName -replace "\..*", ""

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

    $driveErrors    = [System.Collections.Generic.List[string]]::new()
    $driveWarnings  = [System.Collections.Generic.List[string]]::new()
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
            $bar    = Get-VisualBar -Pct $pct
            $tag    = Get-ThresholdTag -Pct $pct
            $prefix = if ($pct -ge 90) { "[DRIVE_CRITICAL] " } else { "" }
            ($prefix + "    " + $_.DeviceID + "  " + $bar + " " + $pct + "% used  (" +
             $usedGB + " GB / " + $totGB + " GB)  Free: " + $freeGB + " GB" + $tag)
        }) -join "`n"
    } else { "    No fixed drives found." }

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
                        $jrePath   = if (Test-Path (Join-Path $candidate "bin\java.exe")) {
                                         $candidate
                                     } else {
                                         Split-Path $jvmDll -Parent
                                     }
                    }
                    if ($regProps.Options) {
                        $optFlat = if ($regProps.Options -is [array]) {
                            $regProps.Options -join ' '
                        } else {
                            [string]$regProps.Options
                        }
                        if ($optFlat -match '(?:^|\s)-Xms(\d+)([kmgKMG])') {
                            $val = [long]$Matches[1]
                            $heapInitMB = switch ($Matches[2].ToUpper()) {
                                'K' { [math]::Round($val / 1KB, 0) }
                                'M' { $val }
                                'G' { $val * 1024 }
                            }
                        }
                        if ($optFlat -match '(?:^|\s)-Xmx(\d+)([kmgKMG])') {
                            $val = [long]$Matches[1]
                            $heapMaxMB = switch ($Matches[2].ToUpper()) {
                                'K' { [math]::Round($val / 1KB, 0) }
                                'M' { $val }
                                'G' { $val * 1024 }
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
                        $gcRecommend.Add("Set -XX:G1HeapRegionSize=16m (Content Server creates large objects; small regions cause humongous allocations)")
                    }
                    $ihop = $gcFlags["InitiatingHeapOccupancyPercent"]
                    if (-not $ihop -or [int]$ihop -gt 45) {
                        $gcRecommend.Add("Set -XX:InitiatingHeapOccupancyPercent=35 (triggers concurrent marking earlier, avoids full GC)")
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

    $out = [System.Collections.Generic.List[string]]::new()
    $out.Add(""); $out.Add("========================================")
    $out.Add("Zone     : $GroupName"); $out.Add("Server   : $ComputerName")
    $out.Add("  Server Uptime: $uptimeStr$recentTag")
    $out.Add("  Memory       : $(Get-VisualBar -Pct $memPct) $memPct% used  ($usedMemGB GB / $totalMemGB GB)  Free: $freeMemGB GB$(Get-ThresholdTag -Pct $memPct)")
    $out.Add("  CPU          : $(Get-VisualBar -Pct $cpuAvg) $cpuAvg%$(Get-ThresholdTag -Pct $cpuAvg)")
    $out.Add("  Drives:")
    foreach ($dline in ($driveSummary -split "`n")) { $out.Add($dline) }
    if ($driveErrors.Count -gt 0) { $out.Add("  [ERROR] Drive critical: " + ($driveErrors -join "; ")) }
    if ($driveWarnings.Count -gt 0) { $out.Add("  [WARN] Drive warning: " + ($driveWarnings -join "; ")) }
    $out.Add("========================================")

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
            Version       = $tomcatVersion;   JrePath       = $jrePath
            HeapInitMB    = $heapInitMB;       HeapMaxMB    = $heapMaxMB
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
                            Status = "ERROR"; Detail = $ir.Error; Ms = $ir.Ms; Slow = ($ir.Ms -ge $InformantWarnMs)
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
                Version       = "";            JrePath       = ""; HeapInitMB = $null; HeapMaxMB = $null
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
            Version       = "";             JrePath       = ""; HeapInitMB = $null; HeapMaxMB = $null
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

    if ($eventLines.Count -gt 0) {
        $out.Add(""); $out.Add("Recent Application Log Events (last 24h, Tomcat/CS related):")
        foreach ($line in $eventLines) { $out.Add("  $line") }
        if ($overallStatus -eq "OK") { $overallStatus = "WARN" }
    }

    Remove-CimSession $session -ErrorAction SilentlyContinue

    $instanceResults.Add([PSCustomObject]@{
        ComputerName     = $ComputerName;  GroupName        = $GroupName
        InstanceLabel    = $ComputerName;  Output           = $out
        CsvRows          = $csvRows;       OverallStatus     = $overallStatus
        TomcatVersion    = $tomcatVersion; EventLines        = $eventLines
        DriveErrors      = $driveErrors;   DriveWarnings     = $driveWarnings
        InformantResults = $allInformant
        GcCollector      = $gcCollector;   GcWarnings        = $gcWarnings
        GcRecommend      = $gcRecommend;   MemPct            = $memPct
        CpuAvg           = $cpuAvg;        MemUsedGB         = $usedMemGB
        MemTotalGB       = $totalMemGB;    MemFreeGB         = $freeMemGB
        DrivesSummary    = $drivesSummaryForCsv; Uptime      = $uptimeStr
        JobLog           = $jobLog
    })
    return $instanceResults
}
#endregion

#region Main
$Credential = $null

$consoleAvailable = $false
try {
    $null = [System.Console]::KeyAvailable
    $consoleAvailable = $true
} catch { }

if ($consoleAvailable) {
    try { while ([System.Console]::KeyAvailable) { [System.Console]::ReadKey($true) | Out-Null } } catch { }
    Write-Host "Use alternate credentials? (y/n)  [auto-skipping in 10 seconds]" -ForegroundColor Cyan
    $useCreds = ""; $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        $keyAvail = $false
        try { $keyAvail = [System.Console]::KeyAvailable } catch { break }
        if ($keyAvail) {
            $key      = [System.Console]::ReadKey($true)
            $useCreds = $key.KeyChar.ToString().ToLower()
            Write-Host $useCreds; break
        }
        Start-Sleep -Milliseconds 100
    }
    if ($useCreds -eq "y") {
        $Credential = Get-Credential -Message "Enter credentials for remote servers"
    }
} else {
    Write-Host "Non-interactive session detected - skipping credential prompt, using default credentials." -ForegroundColor Gray
}

$startTime = Get-Date
Write-Log "Remote Service Status Check" -Color Cyan
Write-Log "Started: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Gray
Write-Log "Log file: $logFile" -Color Gray
Write-Log ""

$jobs = [System.Collections.Generic.List[hashtable]]::new()
foreach ($group in $serverGroups.Keys) {
    foreach ($server in $serverGroups[$group]) {
        while ((Get-Job -State Running).Count -ge $MaxParallelJobs) {
            Start-Sleep -Milliseconds 200
        }
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
        Write-Log "TIMEOUT: [$($entry.Group)] $($entry.Server) - skipping." -Color Yellow
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
    if ($result.JobLog -and $result.JobLog.Count -gt 0) {
        Add-Content -Path $logFile -Value $result.JobLog
    }
}

$prevData = @{}
$prevCsvs = Get-ChildItem -Path $PSScriptRoot -Filter "ServiceCheck_*.csv" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne (Split-Path $csvFile -Leaf) } |
            Sort-Object LastWriteTime -Descending
if ($prevCsvs) {
    $prevRows = Import-Csv -Path $prevCsvs[0].FullName -ErrorAction SilentlyContinue
    foreach ($row in $prevRows) {
        $prevData["$($row.Server)|$($row.ServiceName)"] = $row
    }
    Write-Log "Comparing against previous run: $($prevCsvs[0].Name)" -Color Gray
}

$prevGroup   = $null
$zoneSummary = [ordered]@{}
$allVersions = @{}

foreach ($result in ($results | Sort-Object GroupName, ComputerName)) {
    $grp = $result.GroupName
    if (-not $zoneSummary.Contains($grp)) {
        $zoneSummary[$grp] = @{ OK = 0; WARN = 0; DOWN = 0; CRITICAL = 0 }
    }
    $zoneSummary[$grp][$result.OverallStatus]++

    if ($result.TomcatVersion -and
        $result.TomcatVersion -notin @("N/A","Unknown","Unable to retrieve")) {
        if (-not $allVersions.Contains($grp)) { $allVersions[$grp] = @{} }
        $allVersions[$grp][$result.ComputerName] = $result.TomcatVersion
    }

    if ($grp -ne $prevGroup) {
        Write-Log ""
        Write-Log "########################################" -Color Magenta
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
                if ($prev.Status -ne $row.Status) {
                    $deltaDetails.Add("$($row.ServiceName): Status $($prev.Status) -> $($row.Status)")
                }
                if ($prev.Version -and $row.Version -and $prev.Version -ne $row.Version) {
                    $deltaDetails.Add("$($row.ServiceName): Version $($prev.Version) -> $($row.Version)")
                }
            }
        }
    }
    $hasDelta = $deltaDetails.Count -gt 0
    $isClean  = ($result.OverallStatus -eq "OK") -and (-not $hasDelta)

    if ($QuietOK -and $isClean) {
        Write-Log "  $($result.ComputerName) : OK" -Color Green
        continue
    }

    foreach ($line in $result.Output) {
        $color = "White"
        if     ($line -match "^={3,}|Server   :")                                                        { $color = "Cyan"    }
        elseif ($line -match "Zone     :")                                                                { $color = "Magenta" }
        elseif ($line -match "Recent Reboot")                                                             { $color = "Yellow"  }
        elseif ($line -match "Tomcat Service:|Content Server Service|Informant Health|System Resources") { $color = "Yellow"  }
        elseif ($line -match "\[RUNNING\]|\[SUCCESS\]")                                                  { $color = "Green"   }
        elseif ($line -match "\[STOPPED\]|ERROR:|NOT FOUND|\[FAILURE\]|\[ERROR\]|\[CRITICAL\]")         { $color = "Yellow"  }
        elseif ($line -match "\[WARN\]|\[OTHER\]|\[SLOW\]")                                              { $color = "Yellow"  }
        elseif ($line -match "\[AUTO-RESTART\]")                                                         { $color = "Cyan"    }
        elseif ($line -match "Working Set:|Auto-Restarts:|CPU|Memory|Drive")                             { $color = "Cyan"    }
        elseif ($line -match "Run As:|Restart Config:|Service Uptime:")                                  { $color = "Cyan"    }
        elseif ($line -match "Description:|Display Name:")                                               { $color = "Gray"    }
        Write-Log $line -Color $color
    }

    if ($hasDelta) {
        Write-Log "  >> Changes detected on $($result.ComputerName):" -Color Yellow
        foreach ($d in $deltaDetails) { Write-Log "     $d" -Color Yellow }
    }
}

Write-Log ""
Write-Log "======== Zone Rollup ========" -Color Cyan
foreach ($grp in $zoneSummary.Keys) {
    $s   = $zoneSummary[$grp]
    $tot = $s.OK + $s.WARN + $s.DOWN + $s.CRITICAL
    $col = if ($s.DOWN -gt 0 -or $s.CRITICAL -gt 0) { "Yellow" }
           elseif ($s.WARN -gt 0) { "Yellow" }
           else { "Green" }
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

$allCsvRows = $results | ForEach-Object { $_.CsvRows } | Where-Object { $_ }
if ($allCsvRows) {
    $allCsvRows | Sort-Object Zone, Server, ServiceType |
        Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Log "CSV saved to   : $csvFile" -Color Green
} else {
    Write-Log "No CSV data to export." -Color Yellow
}

# ── HTML ───────────────────────────────────────────────────────────────────────
$htmlRows = $allCsvRows | Sort-Object Zone, Server, ServiceType
$htmlBody = ""

$htmlRows | Group-Object Zone | ForEach-Object {
    $zoneName   = $_.Name
    $zoneRows   = $_.Group
    $zoneStatus = if   ($zoneRows | Where-Object { $_.OverallStatus -in @("DOWN","CRITICAL") }) { "down" }
                  elseif ($zoneRows | Where-Object { $_.OverallStatus -eq "WARN" }) { "warn" }
                  else { "ok" }
    $zoneId     = $zoneName -replace '[^a-zA-Z0-9]', '_'
    $zoneOK     = ($zoneRows | Where-Object { $_.OverallStatus -eq "OK"       }).Count
    $zoneWarn   = ($zoneRows | Where-Object { $_.OverallStatus -eq "WARN"     }).Count
    $zoneCrit   = ($zoneRows | Where-Object { $_.OverallStatus -eq "CRITICAL" }).Count
    $zoneDown   = ($zoneRows | Where-Object { $_.OverallStatus -eq "DOWN"     }).Count
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
        $instSpan = if ($csInstanceNames) { "<span class='srv-inst'>$csInstanceNames</span><span class='srv-sep'>/</span>" } else { "" }
        $serverHeaderLabel =
            "<span class='srv-zone'>$(HtmlEncode $zoneName)</span>" +
            "<span class='srv-sep'>/</span>" +
            $instSpan +
            "<span class='srv-name'>$(HtmlEncode $serverName)</span>"

        $instanceHtml = ""
        $csRows     = $serverRows | Where-Object { $_.ServiceType -eq "ContentServer" }
        $tomcatRow  = $serverRows | Where-Object { $_.ServiceType -eq "Tomcat" }             | Select-Object -First 1
        $csAdminRow = $serverRows | Where-Object { $_.ServiceType -eq "ContentServerAdmin" } | Select-Object -First 1

        $csRows | ForEach-Object {
            $primary  = $_
            $instName = $primary.ServiceName
            $sc       = switch ($primary.OverallStatus) {
                "OK"{"ok"} "WARN"{"warn"} "CRITICAL"{"critical"} "DOWN"{"down"} default {""}
            }
            $instId = $serverId + "_" + ($instName -replace '[^a-zA-Z0-9]', '_')
            $detId  = $instId + "_det"
            $infId  = $instId + "_inf"

            function fmtChip { param($t,$c) "<span class='chip $c'>$t</span>" }
            function fmtVal  {
                param([string]$v)
                $skip = @("","N/A","n/a","null","none","0","unknown")
                if ($skip -contains $v.Trim()) { return $null }
                return $v
            }

            $statusChip  = if ($primary.Status -eq "Running") { fmtChip "RUNNING" "running" }
                           else { fmtChip "STOPPED" "stopped" }
            $overallChip = switch ($primary.OverallStatus) {
                "OK"       { fmtChip "OK"       "ok"       }
                "WARN"     { fmtChip "WARN"      "warn"     }
                "CRITICAL" { fmtChip "CRITICAL"  "critical" }
                "DOWN"     { fmtChip "DOWN"       "down"    }
                default    { fmtChip (HtmlEncode $primary.OverallStatus) "na" }
            }

            $cpuChipClass = if ([double]$primary.CpuPct -ge 90) {"critical"} elseif ([double]$primary.CpuPct -ge 75) {"warn"} else {"ok"}
            $memChipClass = if ([double]$primary.MemPct -ge 90) {"critical"} elseif ([double]$primary.MemPct -ge 75) {"warn"} else {"ok"}

            # ── Inline critical alerts shown on main row ────────────────────────
            $inlineAlerts = ""
            if ($serverResult) {
                foreach ($de in $serverResult.DriveErrors) {
                    $inlineAlerts += "<span class='inline-alert'>&#9632; Drive: $(HtmlEncode $de)</span>"
                }
            }
            if ($serverResult -and $serverResult.GcWarnings) {
                foreach ($gw in $serverResult.GcWarnings) {
                    $inlineAlerts += "<span class='inline-alert'>&#9632; GC: $(HtmlEncode $gw)</span>"
                }
            }
            if ($serverResult -and $serverResult.EventLines -and $serverResult.EventLines.Count -gt 0) {
                $inlineAlerts += "<span class='inline-alert'>&#9632; $($serverResult.EventLines.Count) event log issue(s) in last 24h</span>"
            }
            # Stopped informant checks
            if ($serverResult -and $serverResult.InformantResults -and $serverResult.InformantResults.Contains($instName)) {
                $failedComps = ($serverResult.InformantResults[$instName].Keys | Where-Object {
                    $serverResult.InformantResults[$instName][$_].Status -notin @("SUCCESS")
                })
                foreach ($fc in $failedComps) {
                    $fs = $serverResult.InformantResults[$instName][$fc].Status
                    $inlineAlerts += "<span class='inline-alert'>&#9632; Informant/$fc: $fs</span>"
                }
            }

            # ── Detail grid (skip null/NA values) ─────────────────────────────
            $detCells = ""

            function AddCell {
                param([string]$Label, [string]$Value, [string]$ExtraClass = "", [bool]$ForceShow = $false)
                $skip = @("","N/A","n/a","null","none","unknown")
                if (-not $ForceShow -and ($skip -contains $Value.Trim())) { return "" }
                return "<div class='detail-cell $ExtraClass'><div class='d-label'>$Label</div><div class='d-value'>$Value</div></div>"
            }

            if ($serverResult) {
                $detCells += AddCell "Server Uptime"  (HtmlEncode $serverResult.Uptime)  "" $true
                $detCells += AddCell "Memory"         "$($serverResult.MemUsedGB) GB / $($serverResult.MemTotalGB) GB ($($serverResult.MemPct)%)"  (if($serverResult.MemPct -ge 90){"alert-cell"}elseif($serverResult.MemPct -ge 75){"warn-cell"}else{""})  $true
                $detCells += AddCell "CPU"            "$($serverResult.CpuAvg)%"  (if($serverResult.CpuAvg -ge 90){"alert-cell"}elseif($serverResult.CpuAvg -ge 75){"warn-cell"}else{""})  $true
                $detCells += AddCell "Drives"         (HtmlEncode $serverResult.DrivesSummary)  "full-width"
                foreach ($de in $serverResult.DriveErrors) {
                    $detCells += "<div class='detail-cell alert-cell full-width'><div class='d-label'>Drive Critical</div><div class='d-value'>$(HtmlEncode $de)</div></div>"
                }
                foreach ($dw in $serverResult.DriveWarnings) {
                    $detCells += "<div class='detail-cell warn-cell full-width'><div class='d-label'>Drive Warning</div><div class='d-value'>$(HtmlEncode $dw)</div></div>"
                }
            }
            $detCells += AddCell "Run As"              (HtmlEncode $primary.RunAs)
            $detCells += AddCell "Service Uptime"      (HtmlEncode $primary.ServiceUptime)
            $detCells += AddCell "Restart Config"      (HtmlEncode $primary.RestartConfig)
            $detCells += AddCell "Auto-Restarts (24h)" (HtmlEncode "$($primary.AutoRestarts)")

            if ($tomcatRow) {
                $detCells += AddCell "Tomcat Service"  (HtmlEncode $tomcatRow.ServiceName)
                $detCells += AddCell "Tomcat Version"  (HtmlEncode $tomcatRow.Version)
                $detCells += AddCell "JRE Path"        (HtmlEncode $tomcatRow.JrePath)  "full-width"
                $detCells += AddCell "Heap Xms"        (if($tomcatRow.HeapInitMB){"$($tomcatRow.HeapInitMB) MB"}else{""})
                $detCells += AddCell "Heap Xmx"        (if($tomcatRow.HeapMaxMB){"$($tomcatRow.HeapMaxMB) MB"}else{""})
                $detCells += AddCell "Working Set"     (HtmlEncode $tomcatRow.WorkingSetMB)

                $gcCls = if ($serverResult -and $serverResult.GcWarnings -and $serverResult.GcWarnings.Count -gt 0) { "warn-cell" } else { "" }
                $detCells += AddCell "GC Collector" (HtmlEncode $tomcatRow.GcCollector) $gcCls
                if ($serverResult -and $serverResult.GcWarnings) {
                    foreach ($gw in $serverResult.GcWarnings) {
                        $detCells += "<div class='detail-cell warn-cell full-width'><div class='d-label'>GC Warning</div><div class='d-value'>$(HtmlEncode $gw)</div></div>"
                    }
                }
                if ($serverResult -and $serverResult.GcRecommend -and $serverResult.GcRecommend.Count -gt 0) {
                    $recHtml = "<ol style='margin:4px 0 0 16px;padding:0'>"
                    foreach ($gr in $serverResult.GcRecommend) {
                        $recHtml += "<li style='margin-bottom:4px'>$(HtmlEncode $gr)</li>"
                    }
                    $recHtml += "</ol>"
                    $detCells += "<div class='detail-cell full-width' style='background:#0d1320;border-left:3px solid #3d5a80'>" +
                                 "<div class='d-label' style='color:#8ab4d4'>GC Recommendations</div>" +
                                 "<div class='d-value' style='color:#c9d1d9;font-family:inherit'>$recHtml</div></div>"
                }
            }
            if ($csAdminRow) {
                $detCells += AddCell "CS Admin" "$(HtmlEncode $csAdminRow.ServiceName) [$(HtmlEncode $csAdminRow.Status)]"
            }
            if ($serverResult -and $serverResult.EventLines -and $serverResult.EventLines.Count -gt 0) {
                $evText = ($serverResult.EventLines | ForEach-Object { HtmlEncode $_ }) -join "<br>"
                $detCells += "<div class='detail-cell warn-cell full-width'><div class='d-label'>Event Log (24h)</div><div class='d-value'>$evText</div></div>"
            }
            foreach ($row in $serverRows) {
                $key  = "$($row.Server)|$($row.ServiceName)"
                $prev = $prevData[$key]
                if ($prev -and ($prev.Status -ne $row.Status -or ($prev.Version -and $prev.Version -ne $row.Version))) {
                    $chg  = if ($prev.Status  -ne $row.Status)  { "Status: $(HtmlEncode $prev.Status) &rarr; $(HtmlEncode $row.Status)" }  else { "" }
                    $chgV = if ($prev.Version -and $prev.Version -ne $row.Version) { " Version: $(HtmlEncode $prev.Version) &rarr; $(HtmlEncode $row.Version)" } else { "" }
                    $detCells += "<div class='detail-cell changed-cell full-width'><div class='d-label'>Changed</div><div class='d-value'>$(HtmlEncode $row.ServiceName): $chg$chgV</div></div>"
                }
            }

            # ── Informant grid (collapsed by default) ─────────────────────────
            $infCells     = ""
            $infHasIssues = $false; $infOkCount = 0
            $infToggleHtml = ""

            if ($serverResult -and $serverResult.InformantResults -and
                $serverResult.InformantResults.Contains($instName)) {
                foreach ($comp in $serverResult.InformantResults[$instName].Keys) {
                    $ir      = $serverResult.InformantResults[$instName][$comp]
                    $slowBit = if ($ir.Slow) { " <span class='chip slow'>SLOW</span>" } else { "" }
                    $chipCls = switch ($ir.Status) {
                        "SUCCESS"{"ok"} "FAILURE"{"critical"} "ERROR"{"critical"} default{"warn"}
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
                $infSummary = if ($infHasIssues) { "Informant &mdash; issues detected" } else { "Informant &mdash; $infOkCount / $($serverResult.InformantResults[$instName].Keys.Count) OK" }
                $infToggleHtml = "<tr><td colspan='10' style='padding:0'>" +
                    "<div class='inf-toggle collapsed' onclick='togglePanel(this,&quot;$infId&quot;)' data-target='$infId'>" +
                    "<span class='arrow-icon'></span>$infSummary</div>" +
                    "<div id='$infId' class='hidden-panel'><div class='inf-grid'>$infCells</div></div>" +
                    "</td></tr>"
            }

            $versionDisplay = if ($tomcatRow -and (fmtVal (HtmlEncode $tomcatRow.Version))) { HtmlEncode $tomcatRow.Version } else { "" }
            $wsDisplay      = if ($tomcatRow -and (fmtVal (HtmlEncode $tomcatRow.WorkingSetMB))) { HtmlEncode $tomcatRow.WorkingSetMB } else { "" }
            $heapDisplay    = if ($tomcatRow -and $tomcatRow.HeapInitMB) {
                                  "Xms $($tomcatRow.HeapInitMB)&thinsp;MB / Xmx $($tomcatRow.HeapMaxMB)&thinsp;MB"
                              } else { "" }

            $instanceHtml += "
            <tr class='instance-header $sc' onclick='togglePanel(this, &quot;$detId&quot;)'>
              <td class='td-arrow'><span class='arrow-icon'></span></td>
              <td class='td-inst'><span class='inst-name'>$(HtmlEncode $instName)</span>
                $(if($inlineAlerts){"<div class='inline-alerts'>$inlineAlerts</div>"})
              </td>
              <td>$statusChip</td>
              <td class='td-mono'>$versionDisplay</td>
              <td class='td-mono'>$wsDisplay</td>
              <td class='td-mono'>$heapDisplay</td>
              <td>$(fmtChip "$($primary.CpuPct)%" $cpuChipClass)</td>
              <td>$(fmtChip "$($primary.MemPct)%" $memChipClass)</td>
              <td class='td-mono'>$(if($primary.AutoRestarts -and $primary.AutoRestarts -ne "0" -and $primary.AutoRestarts -ne ""){HtmlEncode "$($primary.AutoRestarts)"}else{""})</td>
              <td>$overallChip</td>
            </tr>
            <tr id='$detId' class='hidden-panel'><td colspan='10' style='padding:0'>
              <div class='detail-panel'><div class='detail-grid'>$detCells</div></div>
            </td></tr>
            $infToggleHtml"
        }

        $serverHtml += "
        <tr class='server-header $serverStatus' onclick='toggleBody(&quot;$serverId&quot;, this)'>
          <td colspan='10'><div class='server-label'><span class='arrow-icon'></span>$serverHeaderLabel</div></td>
        </tr>
        <tbody id='$serverId' class='collapsible' style='display:none'>
          <tr><td colspan='10' style='padding:0'>
            <table class='inner-table'>
              <thead><tr>
                <th class='td-arrow'></th>
                <th>Instance</th><th>Status</th><th>Version</th>
                <th>Working Set</th><th>Heap</th>
                <th>CPU%</th><th>Mem%</th><th>Restarts</th><th>Overall</th>
              </tr></thead>
              <tbody>$instanceHtml</tbody>
            </table>
          </td></tr>
        </tbody>"
    }

    $htmlBody += "
    <tr class='zone-header $zoneStatus collapsed' onclick='toggleBody(&quot;$zoneId&quot;, this)'>
      <td colspan='10'>
        <div class='zone-label'>
          <span class='arrow-icon'></span>
          <span class='z-name'>$(HtmlEncode $zoneName)</span>
          <span class='z-counts'>$zoneOK ok&ensp;$zoneWarn warn&ensp;$zoneCrit crit&ensp;$zoneDown down</span>
        </div>
      </td>
    </tr>
    <tbody id='$zoneId' class='collapsible' style='display:none'>$serverHtml</tbody>"
}

$zoneRollupHtml = foreach ($grp in $zoneSummary.Keys) {
    $s   = $zoneSummary[$grp]
    $cls = if ($s.DOWN -gt 0 -or $s.CRITICAL -gt 0) { "crit" } elseif ($s.WARN -gt 0) { "warn" } else { "ok" }
    "<div class='zone-pill $cls'>" +
    "<span class='pill-name'>$(HtmlEncode $grp)</span>" +
    "<span class='pill-counts'>$($s.OK)ok / $($s.WARN)w / $($s.CRITICAL)c / $($s.DOWN)d</span>" +
    "</div>"
}

# ── Pre-compute values for here-string ─────────────────────────────────────────
# IMPORTANT: Do NOT put complex $(if ...) subexpressions directly inside @" "@.
# Compute them into plain variables first. See DEVELOPER NOTES at top of file.
$htmlGenerated      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$autoRestartLabel   = if ($AutoRestartStopped) { 'On' } else { 'Off' }
$zoneRollupHtmlJoin = $zoneRollupHtml -join ''

# ── HTML here-string ───────────────────────────────────────────────────────────
# WARNING: The closing  "@  MUST be at column 1. No leading spaces. No trailing comments.
$htmlContent = @"
<!DOCTYPE html>
<html lang='en'><head><meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Service Check Report - $timestamp</title>
<style>
:root {
  --bg:       #0f1117;
  --bg2:      #161b22;
  --bg3:      #1c2128;
  --border:   #21262d;
  --text:     #c9d1d9;
  --text-dim: #8b949e;
  --text-hi:  #e6edf3;
  --ok:       #3fb950;
  --warn:     #d29922;
  --crit:     #e8e8e8;
  --crit-bg:  #2a2a2a;
  --crit-bd:  #888888;
  --accent:   #58a6ff;
  --mono:     'Cascadia Code','Consolas',monospace;
}
body.mono-mode {
  --ok:      #e8e8e8;
  --warn:    #aaaaaa;
  --crit:    #ffffff;
  --crit-bg: #333333;
  --crit-bd: #aaaaaa;
  --accent:  #cccccc;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; padding: 24px; }

/* ── Header ── */
.page-header { display: flex; align-items: center; gap: 16px; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--border); }
.logo { width: 38px; height: 38px; background: var(--bg3); border: 1px solid var(--border); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; flex-shrink: 0; color: var(--text-dim); }
.page-header h1 { font-size: 18px; font-weight: 700; color: var(--text-hi); }
.page-header .sub { font-size: 12px; color: var(--text-dim); margin-top: 2px; }
.header-right { margin-left: auto; display: flex; align-items: center; gap: 12px; }
.run-info { font-size: 11px; color: var(--text-dim); text-align: right; line-height: 1.6; }
.run-info strong { color: var(--text); }

/* ── Mono toggle ── */
.toggle-btn { font-size: 11px; padding: 4px 10px; border-radius: 6px; border: 1px solid var(--border); background: var(--bg3); color: var(--text-dim); cursor: pointer; white-space: nowrap; }
.toggle-btn:hover { border-color: var(--text-dim); color: var(--text); }
.toggle-btn.active { border-color: var(--text-dim); color: var(--text-hi); background: var(--bg2); }

/* ── Stats ── */
.stat-bar { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; }
.stat-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 12px 18px; min-width: 100px; text-align: center; }
.stat-num { font-size: 26px; font-weight: 700; line-height: 1; margin-bottom: 3px; }
.stat-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-dim); }
.stat-card.ok   .stat-num { color: var(--ok); }
.stat-card.warn .stat-num { color: var(--warn); }
.stat-card.crit .stat-num { color: var(--crit); }
.stat-card.down .stat-num { color: var(--crit); }
.stat-card.total .stat-num { color: var(--accent); }

/* ── Zone pills ── */
.zone-pills { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 20px; }
.zone-pill { display: inline-flex; align-items: center; gap: 8px; padding: 5px 12px; border-radius: 16px; font-size: 11px; font-weight: 600; border: 1px solid var(--border); background: var(--bg2); cursor: pointer; }
.zone-pill .pill-name { color: var(--text-hi); }
.zone-pill .pill-counts { font-size: 10px; color: var(--text-dim); }
.zone-pill.ok   { border-color: #2d5a3d; }
.zone-pill.warn { border-color: #5a4a1a; }
.zone-pill.crit { border-color: var(--crit-bd); }

/* ── Table shell ── */
.table-wrap { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
table { border-collapse: collapse; width: 100%; }
th { background: var(--bg3); color: var(--text-dim); font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); white-space: nowrap; }
td { padding: 0; border: none; font-size: 13px; }

/* ── Zone row ── */
.zone-header td { padding: 10px 14px; font-size: 13px; font-weight: 700; cursor: pointer; background: var(--bg3); border-top: 2px solid var(--border); border-bottom: 1px solid var(--border); user-select: none; }
.zone-header.ok   td { border-left: 3px solid #2d5a3d; }
.zone-header.warn td { border-left: 3px solid #5a4a1a; }
.zone-header.down td, .zone-header.critical td { border-left: 3px solid var(--crit-bd); }
.zone-label { display: flex; align-items: center; gap: 10px; }
.z-name { color: var(--accent); } .z-counts { font-size: 11px; color: var(--text-dim); font-weight: 400; }

/* ── Server row ── */
.server-header td { padding: 8px 14px 8px 26px; cursor: pointer; background: var(--bg2); border-bottom: 1px solid var(--border); user-select: none; }
.server-header.ok   td { border-left: 3px solid #2d5a3d; }
.server-header.warn td { border-left: 3px solid #5a4a1a; }
.server-header.down td, .server-header.critical td { border-left: 3px solid var(--crit-bd); }
.server-label { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.srv-zone { font-size: 10px; color: var(--text-dim); } .srv-inst { font-size: 12px; color: var(--ok); font-weight: 700; }
.srv-name { font-size: 13px; color: var(--text); } .srv-sep { color: var(--border); }

/* ── Inner table ── */
.inner-table { width: 100%; border-collapse: collapse; }
.inner-table th { background: var(--bg); padding: 7px 10px; font-size: 10px; }
.instance-header td { padding: 7px 10px; cursor: pointer; background: var(--bg); border-bottom: 1px solid var(--border); user-select: none; }
.instance-header:hover td { background: var(--bg2); }
.inst-name { color: var(--text-hi); font-weight: 600; font-size: 13px; }
.inline-alerts { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 4px; }
.inline-alert { font-size: 10px; font-weight: 600; color: var(--crit); background: var(--crit-bg); border: 1px solid var(--crit-bd); border-radius: 4px; padding: 1px 6px; letter-spacing: 0.02em; }
body.mono-mode .inline-alert { color: #fff; background: #222; border-color: #888; }

/* ── Chips ── */
.chip { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 700; letter-spacing: 0.04em; white-space: nowrap; border: 1px solid transparent; }
.chip.ok, .chip.running { color: var(--ok); border-color: #2d5a3d; background: #0d1f12; }
.chip.warn { color: var(--warn); border-color: #5a4a1a; background: #1a1400; }
.chip.critical, .chip.stopped, .chip.down { color: var(--crit); border-color: var(--crit-bd); background: var(--crit-bg); }
.chip.slow { color: var(--warn); border-color: #5a4a1a; background: #1a1400; }
.chip.na { color: var(--text-dim); border-color: var(--border); background: var(--bg2); }
body.mono-mode .chip.ok, body.mono-mode .chip.running { color: #fff; border-color: #666; background: #1e1e1e; }
body.mono-mode .chip.warn  { color: #ccc; border-color: #555; background: #1e1e1e; }
body.mono-mode .chip.critical, body.mono-mode .chip.stopped, body.mono-mode .chip.down { color: #fff; border-color: #aaa; background: #333; }

/* ── Arrow icon ── */
.arrow-icon { display: inline-block; width: 14px; height: 14px; border-radius: 3px; background: var(--bg3); border: 1px solid var(--border); text-align: center; line-height: 13px; font-size: 8px; color: var(--text-dim); vertical-align: middle; margin-right: 6px; flex-shrink: 0; transition: transform 0.15s; }
.arrow-icon::after { content: '\25BC'; }
.collapsed .arrow-icon::after { content: '\25B6'; }
.td-arrow { width: 28px; }
.td-inst  { min-width: 180px; }
.td-mono  { font-family: var(--mono); font-size: 11px; padding: 7px 10px; color: var(--text-dim); }

/* ── Detail panel ── */
.detail-panel { background: var(--bg); border-bottom: 1px solid var(--border); }
.detail-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 1px; background: var(--border); border-top: 1px solid var(--border); }
.detail-cell { background: var(--bg); padding: 7px 14px; display: flex; flex-direction: column; gap: 2px; }
.d-label { font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em; color: var(--text-dim); }
.d-value { font-size: 11px; color: var(--text); word-break: break-all; font-family: var(--mono); }
.detail-cell.full-width { grid-column: 1 / -1; }
.detail-cell.alert-cell   { background: #1a1a1a; }
.detail-cell.alert-cell   .d-label { color: var(--crit); }
.detail-cell.alert-cell   .d-value { color: var(--crit); font-weight: 600; }
.detail-cell.warn-cell    { background: #141200; }
.detail-cell.warn-cell    .d-label { color: var(--warn); }
.detail-cell.warn-cell    .d-value { color: var(--warn); }
.detail-cell.changed-cell { background: #141200; }
.detail-cell.changed-cell .d-label { color: var(--warn); }
.detail-cell.changed-cell .d-value { color: var(--warn); }

/* ── Informant toggle ── */
.inf-toggle { display: flex; align-items: center; gap: 6px; padding: 6px 14px; cursor: pointer; background: var(--bg); border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); user-select: none; font-size: 11px; font-weight: 600; color: var(--accent); }
.inf-toggle:hover { background: var(--bg2); }
.inf-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(190px, 1fr)); gap: 1px; background: var(--border); }
.inf-cell { background: var(--bg); padding: 6px 12px; display: flex; align-items: center; gap: 8px; }
.inf-comp { font-size: 11px; font-weight: 600; color: var(--text-dim); width: 90px; flex-shrink: 0; font-family: var(--mono); }
.inf-ms { font-size: 10px; color: var(--border); margin-left: auto; }

/* ── Misc ── */
.hidden-panel { display: none; }
.collapsible  { display: table-row-group; }
.text-muted   { color: var(--text-dim); }
</style>
</head><body>

<div class='page-header'>
  <div class='logo'>&#9830;</div>
  <div>
    <h1>Service Check Report</h1>
    <div class='sub'>Tomcat &middot; Content Server &middot; CS Admin</div>
  </div>
  <div class='header-right'>
    <button class='toggle-btn' id='monoBtn' onclick='toggleMono()'>Mono</button>
    <div class='run-info'>
      <strong>Generated:</strong> $htmlGenerated<br>
      <strong>Servers:</strong> $serverCount &nbsp;&middot;&nbsp; <strong>Auto-restart:</strong> $autoRestartLabel
    </div>
  </div>
</div>

<div class='stat-bar' id='stat-bar'></div>

<div class='zone-pills' id='zone-pills'>$zoneRollupHtmlJoin</div>

<div class='table-wrap'>
<table id='main-table'>
  <thead><tr>
    <th class='td-arrow'></th>
    <th>Instance</th><th>Status</th><th>Version</th>
    <th>Working Set</th><th>Heap</th>
    <th>CPU%</th><th>Mem%</th><th>Restarts</th><th>Overall</th>
  </tr></thead>
  <tbody>$htmlBody</tbody>
</table>
</div>

<script>
function toggleBody(id, row) {
  var el = document.getElementById(id);
  if (!el) return;
  var hidden = el.style.display === 'none' || el.style.display === '';
  el.style.display = hidden ? 'table-row-group' : 'none';
  row.classList.toggle('collapsed', !hidden);
}

function togglePanel(row, id) {
  var el = document.getElementById(id);
  if (!el) return;
  var hidden = el.style.display === 'none' || el.style.display === '';
  el.style.display = hidden ? 'table-row' : 'none';
  row.classList.toggle('collapsed', !hidden);
}

function toggleMono() {
  document.body.classList.toggle('mono-mode');
  var btn = document.getElementById('monoBtn');
  btn.classList.toggle('active');
}

// Wire zone pills to expand their zone
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.zone-pill').forEach(function(pill) {
    pill.addEventListener('click', function() {
      var name = pill.querySelector('.pill-name').textContent.trim();
      document.querySelectorAll('.zone-header').forEach(function(row) {
        var zname = row.querySelector('.z-name');
        if (zname && zname.textContent.trim() === name) {
          var id = row.nextElementSibling;
          while (id && id.tagName !== 'TBODY') { id = id.nextElementSibling; }
          if (id) {
            var hidden = id.style.display === 'none' || id.style.display === '';
            id.style.display = hidden ? 'table-row-group' : 'none';
            row.classList.toggle('collapsed', !hidden);
          }
        }
      });
    });
  });

  // Build stat bar
  var ok=0, warn=0, crit=0, down=0;
  document.querySelectorAll('.instance-header').forEach(function(r) {
    if      (r.classList.contains('ok'))       ok++;
    else if (r.classList.contains('warn'))     warn++;
    else if (r.classList.contains('critical')) crit++;
    else if (r.classList.contains('down'))     down++;
  });
  document.getElementById('stat-bar').innerHTML =
    mk(ok+warn+crit+down,'Total','total') +
    mk(ok,'Healthy','ok') +
    mk(warn,'Warning','warn') +
    mk(crit,'Critical','crit') +
    mk(down,'Down','down');
});

function mk(n,l,c) {
  return "<div class='stat-card "+c+"'><div class='stat-num'>"+n+"</div><div class='stat-label'>"+l+"</div></div>";
}
</script>
</body></html>
"@
# ↑ The  "@  above MUST stay at column 1. No leading spaces. See DEVELOPER NOTES at top.

$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($htmlFile, $htmlContent, $utf8Bom)
Write-Log "HTML report    : $htmlFile" -Color Green

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
    } catch {
        Write-Log "Failed to send alert email: $_" -Color Yellow
    }
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

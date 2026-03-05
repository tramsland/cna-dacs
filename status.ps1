#Requires -Version 5.1
# Remote Service Status Checker (Parallel with Logging)
# Checks Tomcat, Content Server, and Content Server Admin on remote Windows servers
# v3.1 -- PS 5.1 compatible, HTML escaping fixed
#
# POWERSHELL 5.1 COMPATIBILITY NOTES:
#   - 'return <expr>' with an inline if/else is NOT valid in PS 5.1.
#     Use explicit: if (...) { return x } else { return y }
#   - 'switch ($true) { { expr } { val; break } }' works in PS 5.1 but
#     chained if/elseif is safer and avoids subtle scoping issues in jobs.
#   - Ternary operator (?:) does NOT exist until PS 7. Use if/else.
#   - Null-coalescing (??) does NOT exist until PS 7. Use if/else.
#   - ForEach-Object -Parallel does NOT exist until PS 7. Use Start-Job.
#
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  HTML GENERATION - POWERSHELL STRING ESCAPING RULES                        ║
# ║  All HTML fragments built via double-quoted string concatenation            ║
# ║  (NOT here-strings). This means:                                            ║
# ║                                                                              ║
# ║  1. HTML attribute quotes MUST use backtick-escaped doubles: `"value`"      ║
# ║     WRONG : class='foo'   onclick='fn()'                                    ║
# ║     RIGHT : class=`"foo`" onclick=`"fn()`"                                  ║
# ║                                                                              ║
# ║  2. &quot; HTML entities MUST NOT be used — PowerShell sees bare & as an   ║
# ║     operator and throws a parse error.                                       ║
# ║     WRONG : onclick='toggleRow(this, &quot;$id&quot;)'                      ║
# ║     RIGHT : onclick=`"toggleRow(this,'$id')`"                               ║
# ║                                                                              ║
# ║  3. JS string arguments inside onclick use single quotes around PS vars     ║
# ║     so no additional escaping is needed inside the JS call:                 ║
# ║     RIGHT : onclick=`"toggleRow(this,'$someVar')`"                          ║
# ║                                                                              ║
# ║  4. Helper functions use inline typed params to avoid parser ambiguity      ║
# ║     with param() blocks inside nested scriptblocks:                         ║
# ║     WRONG : function IsBlank { param($v) return ... }                       ║
# ║     RIGHT : function IsBlank([string]$v) { return ... }                     ║
# ║                                                                              ║
# ║  5. Informant toggle state is set via inline style="display:..." at render  ║
# ║     time. Do NOT use class='hidden-panel' + JS classList check — the        ║
# ║     toggleRow() function only reads/writes el.style.display, so the panel   ║
# ║     must start with a real inline style or it cannot be toggled closed.     ║
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
$portCheckTimeout = 3   # reserved for future port checks
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

    # Counts System event ID 7034 (service crashed) for this service in the last 24h.
    # ID 7036 intentionally excluded — fires for normal start/stop transitions.
    # PS 5.1 fix: cannot use 'return if (...)' — must use explicit if/else return
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
        if ($Pct -ge 90)     { return " [CRITICAL]" }
        elseif ($Pct -ge 75) { return " [WARN]" }
        else                  { return "" }
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
    $memBar     = Get-VisualBar -Pct $memPct
    $memTag     = Get-ThresholdTag -Pct $memPct
    $uptimeStr  = Get-UptimeString -LastBootTime $os.LastBootUpTime
    $recentTag  = if (((Get-Date) - $os.LastBootUpTime).TotalHours -lt 24) { "  [WARN - Recent Reboot]" } else { "" }

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
            $bar    = Get-VisualBar -Pct $pct
            $tag    = Get-ThresholdTag -Pct $pct
            $prefix = if ($pct -ge 90) { "[DRIVE_CRITICAL] " } else { "" }
            ($prefix + "    " + $_.DeviceID + "  " + $bar + " " + $pct + "% used  (" +
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

    # ── Tomcat version + JVM config (via Invoke-Command) ───────────────────────
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
                        if (Test-Path (Join-Path $candidate "bin\java.exe")) {
                            $jrePath = $candidate
                        } else {
                            $jrePath = Split-Path $jvmDll -Parent
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

                # ── GC analysis via jcmd ───────────────────────────────────────
                # PS 5.1 fix: switch ($true) with break works but if/elseif is
                # safer inside Invoke-Command scriptblocks — use that instead.
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
                        if     ($gcFlags["UseZGC"]             -eq $true) { $gcCollector = "ZGC"             }
                        elseif ($gcFlags["UseShenandoahGC"]    -eq $true) { $gcCollector = "Shenandoah"      }
                        elseif ($gcFlags["UseG1GC"]            -eq $true) { $gcCollector = "G1GC"            }
                        elseif ($gcFlags["UseConcMarkSweepGC"] -eq $true) { $gcCollector = "CMS"             }
                        elseif ($gcFlags["UseParallelGC"]      -eq $true) { $gcCollector = "ParallelGC"      }
                        elseif ($gcFlags["UseSerialGC"]        -eq $true) { $gcCollector = "SerialGC"        }
                        else                                               { $gcCollector = "G1GC (default)"  }
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
    $out.Add("  Memory       : $memBar $memPct% used  ($usedMemGB GB / $totalMemGB GB)  Free: $freeMemGB GB$memTag")
    $out.Add("  CPU          : $(Get-VisualBar -Pct $cpuAvg) $cpuAvg%$(Get-ThresholdTag -Pct $cpuAvg)")
    $out.Add("  Drives:")
    foreach ($dline in ($driveSummary -split "`n")) { $out.Add($dline) }
    if ($driveErrors.Count   -gt 0) { $out.Add("  [ERROR] Drive critical: " + ($driveErrors   -join "; ")) }
    if ($driveWarnings.Count -gt 0) { $out.Add("  [WARN] Drive warning: "   + ($driveWarnings -join "; ")) }
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
            $key      = [System.Console]::ReadKey($true)
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
    if ($result.JobLog -and $result.JobLog.Count -gt 0) {
        Add-Content -Path $logFile -Value $result.JobLog
    }
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

    if ($QuietOK -and $isClean) { Write-Log "  $($result.ComputerName) : OK" -Color Green; continue }

    foreach ($line in $result.Output) {
        $color = "White"
        if     ($line -match "^={3,}|Server   :")                                                        { $color = "Cyan"    }
        elseif ($line -match "Zone     :")                                                                { $color = "Magenta" }
        elseif ($line -match "Recent Reboot")                                                             { $color = "Yellow"  }
        elseif ($line -match "Tomcat Service:|Content Server Service|Informant Health|System Resources") { $color = "Yellow"  }
        elseif ($line -match "^\[DRIVE_CRITICAL\] ")                                                     { $color = "Red"     }
        elseif ($line -match "\[RUNNING\]|\[SUCCESS\]")                                                  { $color = "Green"   }
        elseif ($line -match "\[STOPPED\]|ERROR:|NOT FOUND|\[FAILURE\]|\[ERROR\]|\[CRITICAL\]")         { $color = "Red"     }
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

# ── Zone rollup ────────────────────────────────────────────────────────────────
Write-Log ""
Write-Log "======== Zone Rollup ========" -Color Cyan
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

# ── CSV ────────────────────────────────────────────────────────────────────────
$allCsvRows = $results | ForEach-Object { $_.CsvRows } | Where-Object { $_ }
if ($allCsvRows) {
    $allCsvRows | Sort-Object Zone, Server, ServiceType |
        Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Log "CSV saved to   : $csvFile" -Color Green
} else {
    Write-Log "No CSV data to export." -Color Yellow
}

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  HTML GENERATION — see escaping rules at top of file before editing        ║
# ║  All HTML attribute quotes use backtick-escaped doubles (`")               ║
# ║  No &quot; entities. No single-quoted HTML attrs in PS double-quoted strings║
# ║  Informant toggle state set via inline style="display:..." not CSS class   ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
$htmlRows = $allCsvRows | Sort-Object Zone, Server, ServiceType
$htmlBody = ""

# Helper: returns $true if a value is blank, null, "N/A", or "null"
# Inline typed param used (not param() block) to avoid PS 5.1 parser ambiguity
function IsBlank([string]$v) { return (-not $v -or $v -match '^\s*$' -or $v -eq 'N/A' -or $v -eq 'null') }

# Helper: renders a status chip span. Inline typed params — see escaping rules.
function fmtChip([string]$t, [string]$c) { return "<span class=`"chip $c`">$t</span>" }

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
            "<span class=`"srv-inst`">$csInstanceNames</span><span class=`"srv-sep`">/</span>"
        } else { "" }
        $serverHeaderLabel =
            "<span class=`"srv-zone`">$(HtmlEncode $zoneName)</span>" +
            "<span class=`"srv-sep`">/</span>" + $instSpan +
            "<span class=`"srv-name`">$(HtmlEncode $serverName)</span>"

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

            $statusChip  = if ($primary.Status -eq "Running") { fmtChip "RUNNING" "running" } else { fmtChip "STOPPED" "stopped" }
            $overallChip = switch ($primary.OverallStatus) {
                "OK"       { fmtChip "OK"      "ok"       }
                "WARN"     { fmtChip "WARN"     "warn"     }
                "CRITICAL" { fmtChip "CRITICAL" "critical" }
                "DOWN"     { fmtChip "DOWN"     "down"     }
                default    { fmtChip (HtmlEncode $primary.OverallStatus) "na" }
            }
            $versionVal = if ($tomcatRow -and -not (IsBlank $tomcatRow.Version))     { HtmlEncode $tomcatRow.Version }      else { "" }
            $wsVal      = if ($tomcatRow -and -not (IsBlank $tomcatRow.WorkingSetMB)) { HtmlEncode $tomcatRow.WorkingSetMB } else { "" }
            $heapVal    = if ($tomcatRow -and $tomcatRow.HeapInitMB) {
                              "Xms: $(HtmlEncode $tomcatRow.HeapInitMB) MB / Xmx: $(HtmlEncode $tomcatRow.HeapMaxMB) MB"
                          } else { "" }
            $cpuChipClass = if ([double]$primary.CpuPct -ge 90) { "critical" } elseif ([double]$primary.CpuPct -ge 75) { "warn" } else { "ok" }
            $memChipClass = if ([double]$primary.MemPct -ge 90) { "critical" } elseif ([double]$primary.MemPct -ge 75) { "warn" } else { "ok" }

            # ── Detail grid — only emit cells with real values ─────────────────
            $detCells = ""
            if ($serverResult) {
                if (-not (IsBlank $serverResult.Uptime)) {
                    $detCells += "<div class=`"detail-cell`"><div class=`"d-label`">Server Uptime</div><div class=`"d-value`">$(HtmlEncode $serverResult.Uptime)</div></div>"
                }
                if ($serverResult.MemTotalGB -gt 0) {
                    $detCells += "<div class=`"detail-cell`"><div class=`"d-label`">Memory</div><div class=`"d-value`">$($serverResult.MemUsedGB) GB / $($serverResult.MemTotalGB) GB ($($serverResult.MemPct)%)</div></div>"
                }
                if ($null -ne $serverResult.CpuAvg) {
                    $detCells += "<div class=`"detail-cell`"><div class=`"d-label`">CPU (avg)</div><div class=`"d-value`">$($serverResult.CpuAvg)%</div></div>"
                }
                if (-not (IsBlank $serverResult.DrivesSummary)) {
                    $detCells += "<div class=`"detail-cell full-width`"><div class=`"d-label`">Drives</div><div class=`"d-value`">$(HtmlEncode $serverResult.DrivesSummary)</div></div>"
                }
                foreach ($de in $serverResult.DriveErrors) {
                    $detCells += "<div class=`"detail-cell critical-cell full-width`"><div class=`"d-label`">&#9888; Drive Critical</div><div class=`"d-value`">$(HtmlEncode $de)</div></div>"
                }
                foreach ($dw in $serverResult.DriveWarnings) {
                    $detCells += "<div class=`"detail-cell warn-cell full-width`"><div class=`"d-label`">Drive Warning</div><div class=`"d-value`">$(HtmlEncode $dw)</div></div>"
                }
            }
            if (-not (IsBlank $primary.RunAs))         { $detCells += "<div class=`"detail-cell`"><div class=`"d-label`">Run As</div><div class=`"d-value`">$(HtmlEncode $primary.RunAs)</div></div>" }
            if (-not (IsBlank $primary.ServiceUptime)) { $detCells += "<div class=`"detail-cell`"><div class=`"d-label`">Service Uptime</div><div class=`"d-value`">$(HtmlEncode $primary.ServiceUptime)</div></div>" }
            if (-not (IsBlank $primary.RestartConfig)) { $detCells += "<div class=`"detail-cell`"><div class=`"d-label`">Restart Config</div><div class=`"d-value`">$(HtmlEncode $primary.RestartConfig)</div></div>" }
            if ($null -ne $primary.AutoRestarts -and "$($primary.AutoRestarts)" -ne "") {
                $detCells += "<div class=`"detail-cell`"><div class=`"d-label`">Auto-Restarts (24h)</div><div class=`"d-value`">$(HtmlEncode "$($primary.AutoRestarts)")</div></div>"
            }
            if ($tomcatRow) {
                if (-not (IsBlank $tomcatRow.ServiceName)) { $detCells += "<div class=`"detail-cell`"><div class=`"d-label`">Tomcat Service</div><div class=`"d-value`">$(HtmlEncode $tomcatRow.ServiceName)</div></div>" }
                if (-not (IsBlank $tomcatRow.Version))     { $detCells += "<div class=`"detail-cell`"><div class=`"d-label`">Tomcat Version</div><div class=`"d-value`">$(HtmlEncode $tomcatRow.Version)</div></div>" }
                if (-not (IsBlank $tomcatRow.JrePath))     { $detCells += "<div class=`"detail-cell full-width`"><div class=`"d-label`">JRE Path</div><div class=`"d-value`">$(HtmlEncode $tomcatRow.JrePath)</div></div>" }
                if ($tomcatRow.HeapInitMB) { $detCells += "<div class=`"detail-cell`"><div class=`"d-label`">Heap Xms</div><div class=`"d-value`">$($tomcatRow.HeapInitMB) MB</div></div>" }
                if ($tomcatRow.HeapMaxMB)  { $detCells += "<div class=`"detail-cell`"><div class=`"d-label`">Heap Xmx</div><div class=`"d-value`">$($tomcatRow.HeapMaxMB) MB</div></div>" }
                if (-not (IsBlank $tomcatRow.WorkingSetMB)) { $detCells += "<div class=`"detail-cell`"><div class=`"d-label`">Working Set</div><div class=`"d-value`">$(HtmlEncode $tomcatRow.WorkingSetMB)</div></div>" }
                if (-not (IsBlank $tomcatRow.GcCollector)) {
                    $gcCls = if ($serverResult -and $serverResult.GcWarnings -and $serverResult.GcWarnings.Count -gt 0) { "warn-cell" } else { "" }
                    $detCells += "<div class=`"detail-cell $gcCls`"><div class=`"d-label`">GC Collector</div><div class=`"d-value`">$(HtmlEncode $tomcatRow.GcCollector)</div></div>"
                }
                if ($serverResult -and $serverResult.GcWarnings) {
                    foreach ($gw in $serverResult.GcWarnings) {
                        $detCells += "<div class=`"detail-cell warn-cell full-width`"><div class=`"d-label`">GC Warning</div><div class=`"d-value`">$(HtmlEncode $gw)</div></div>"
                    }
                }
                if ($serverResult -and $serverResult.GcRecommend -and $serverResult.GcRecommend.Count -gt 0) {
                    $recHtml = "<ol style=`"margin:4px 0 0 16px;padding:0`">"
                    foreach ($gr in $serverResult.GcRecommend) { $recHtml += "<li style=`"margin-bottom:4px`">$(HtmlEncode $gr)</li>" }
                    $recHtml += "</ol>"
                    $detCells += "<div class=`"detail-cell full-width`" style=`"background:#0d1320;border-left:3px solid #1f6feb`">" +
                                 "<div class=`"d-label`" style=`"color:#79c0ff`">GC Recommendations</div>" +
                                 "<div class=`"d-value`" style=`"color:#c9d1d9;font-family:inherit`">$recHtml</div></div>"
                }
            }
            if ($csAdminRow -and -not (IsBlank $csAdminRow.ServiceName)) {
                $detCells += "<div class=`"detail-cell`"><div class=`"d-label`">CS Admin</div><div class=`"d-value`">$(HtmlEncode $csAdminRow.ServiceName) [$(HtmlEncode $csAdminRow.Status)]</div></div>"
            }
            if ($serverResult -and $serverResult.EventLines -and $serverResult.EventLines.Count -gt 0) {
                $evText = ($serverResult.EventLines | ForEach-Object { HtmlEncode $_ }) -join "<br>"
                $detCells += "<div class=`"detail-cell warn-cell full-width`"><div class=`"d-label`">Event Log (24h)</div><div class=`"d-value`">$evText</div></div>"
            }
            foreach ($row in $serverRows) {
                $key  = "$($row.Server)|$($row.ServiceName)"
                $prev = $prevData[$key]
                if ($prev -and ($prev.Status -ne $row.Status -or ($prev.Version -and $prev.Version -ne $row.Version))) {
                    $chg  = if ($prev.Status -ne $row.Status) { "Status: $(HtmlEncode $prev.Status) &rarr; $(HtmlEncode $row.Status)" } else { "" }
                    $chgV = if ($prev.Version -and $prev.Version -ne $row.Version) { " Version: $(HtmlEncode $prev.Version) &rarr; $(HtmlEncode $row.Version)" } else { "" }
                    $detCells += "<div class=`"detail-cell changed-cell full-width`"><div class=`"d-label`">Changed</div><div class=`"d-value`">$(HtmlEncode $row.ServiceName): $chg$chgV</div></div>"
                }
            }

            # ── Informant grid ─────────────────────────────────────────────────
            # Toggle state is set via inline style="display:..." at render time.
            # Do NOT switch to class="hidden-panel" — toggleRow() only reads
            # el.style.display and cannot close a panel that has no inline style.
            $infCells      = ""
            $infHasIssues  = $false
            $infOkCount    = 0
            $infToggleHtml = ""

            if ($serverResult -and $serverResult.InformantResults -and
                $serverResult.InformantResults.Contains($instName)) {
                foreach ($comp in $serverResult.InformantResults[$instName].Keys) {
                    $ir      = $serverResult.InformantResults[$instName][$comp]
                    $slowBit = if ($ir.Slow) { " <span class=`"chip slow`">SLOW</span>" } else { "" }
                    $chipCls = switch ($ir.Status) {
                        "SUCCESS" { "ok"      }
                        "FAILURE" { "failure" }
                        "ERROR"   { "error"   }
                        default   { "other"   }
                    }
                    if ($ir.Status -ne "SUCCESS") { $infHasIssues = $true } else { $infOkCount++ }
                    $detail = if ($ir.Status -notin @("SUCCESS","FAILURE")) {
                                  "<span class=`"text-muted`" style=`"font-size:10px`">$(HtmlEncode $ir.Detail)</span>"
                              } else { "" }
                    $infCells += "<div class=`"inf-cell`">" +
                                 "<span class=`"inf-comp`">$(HtmlEncode $comp)</span>" +
                                 "<span class=`"chip $chipCls`">$(HtmlEncode $ir.Status)</span>$slowBit$detail" +
                                 "<span class=`"inf-ms`">$($ir.Ms)ms</span></div>"
                }
                $infLabel        = if ($infHasIssues) { "Informant  Issues detected" } else { "Informant  $infOkCount OK" }
                $infExpanded     = if ($infHasIssues) { "block" } else { "none" }
                $infCollapsedCls = if ($infHasIssues) { "" } else { "collapsed" }
                $infToggleHtml   = "<tr><td colspan=`"10`">" +
                    "<div class=`"inf-toggle $infCollapsedCls`" onclick=`"toggleRow(this,'$infId')`" data-target=`"$infId`">" +
                    "<span class=`"arrow`">v</span> $infLabel</div>" +
                    "<div id=`"$infId`" style=`"display:$infExpanded`"><div class=`"inf-grid`">$infCells</div></div>" +
                    "</td></tr>"
            }

            # ── Instance table row — suppress empty columns ────────────────────
            $versionTd = if (-not (IsBlank $versionVal)) { "<td class=`"monospace`" style=`"padding:8px 12px;font-size:12px`">$versionVal</td>" } else { "<td></td>" }
            $wsTd      = if (-not (IsBlank $wsVal))      { "<td class=`"monospace`" style=`"padding:8px 12px;font-size:12px`">$wsVal</td>" }      else { "<td></td>" }
            $heapTd    = if (-not (IsBlank $heapVal))    { "<td class=`"monospace`" style=`"padding:8px 12px;font-size:12px`">$heapVal</td>" }    else { "<td></td>" }

            $instanceHtml += "<tr class=`"instance-header $sc`" onclick=`"toggleRow(this,'$detId')`">" +
              "<td style=`"padding:8px 12px`"><span class=`"arrow`">v</span></td>" +
              "<td><span class=`"inst-label`"><span class=`"inst-name-text`">$(HtmlEncode $instName)</span></span></td>" +
              "<td>$statusChip</td>" +
              $versionTd + $wsTd + $heapTd +
              "<td>$(fmtChip "$($primary.CpuPct)%" $cpuChipClass)</td>" +
              "<td>$(fmtChip "$($primary.MemPct)%" $memChipClass)</td>" +
              "<td style=`"padding:8px 12px;font-size:12px`">$(HtmlEncode "$($primary.AutoRestarts)")</td>" +
              "<td>$overallChip</td></tr>" +
              "<tr id=`"$detId`" style=`"display:none`"><td colspan=`"10`" style=`"padding:0`">" +
              "<div class=`"detail-panel`"><div class=`"detail-grid`">$detCells</div></div>" +
              "</td></tr>" +
              $infToggleHtml
        }

        $serverHtml += "<tr class=`"server-header $serverStatus`" onclick=`"toggleRow(this,'$serverId')`">" +
          "<td colspan=`"10`"><div class=`"server-label`"><span class=`"arrow`">v</span>$serverHeaderLabel</div></td></tr>" +
          "<tbody id=`"$serverId`" class=`"collapsible`">" +
          "<tr><td colspan=`"10`" style=`"padding:0`">" +
          "<table class=`"inner-table`"><thead><tr>" +
          "<th style=`"width:32px`"></th>" +
          "<th>Instance</th><th>Status</th><th>Version</th>" +
          "<th>Working Set</th><th>Heap Xms/Xmx</th>" +
          "<th>CPU%</th><th>Mem%</th><th>Restarts</th><th>Overall</th>" +
          "</tr></thead><tbody>$instanceHtml</tbody></table>" +
          "</td></tr></tbody>"
    }

    $htmlBody += "<tr class=`"zone-header $zoneStatus`" onclick=`"toggleRow(this,'$zoneId')`">" +
      "<td colspan=`"10`"><div class=`"zone-label`">" +
      "<span class=`"arrow`">v</span>" +
      "<span class=`"z-name`">$(HtmlEncode $zoneName)</span>" +
      "<span class=`"z-counts`">$zoneOK OK / $zoneWarn WARN / $zoneCrit CRIT / $zoneDown DOWN</span>" +
      "</div></td></tr>" +
      "<tbody id=`"$zoneId`" class=`"collapsible`">$serverHtml</tbody>"
}

# ── Zone rollup pills + critical summary banner ────────────────────────────────
$zoneRollupHtml = foreach ($grp in $zoneSummary.Keys) {
    $s   = $zoneSummary[$grp]
    $cls = if ($s.DOWN -gt 0 -or $s.CRITICAL -gt 0) { "crit" } elseif ($s.WARN -gt 0) { "warn" } else { "ok" }
    "<div class=`"zone-pill $cls`">" +
    "<span class=`"pill-name`">$(HtmlEncode $grp)</span>" +
    "<span class=`"pill-counts`">$($s.OK) OK / $($s.WARN) W / $($s.CRITICAL) C / $($s.DOWN) D</span>" +
    "</div>"
}

$criticalSummaryHtml = ""
$critRows = $allCsvRows | Where-Object { $_.OverallStatus -in @("DOWN","CRITICAL") }
if ($critRows) {
    $cards = ""
    foreach ($r in ($critRows | Sort-Object Zone, Server, ServiceType)) {
        $icon = if ($r.OverallStatus -eq "DOWN") { "✕" } else { "⚑" }
        $cards += "<div class=`"crit-card`">" +
            "<span class=`"crit-icon`">$icon</span>" +
            "<div class=`"crit-body`">" +
            "<div class=`"crit-title`">$(HtmlEncode $r.Server)</div>" +
            "<div class=`"crit-sub`">$(HtmlEncode $r.Zone) &nbsp;/&nbsp; $(HtmlEncode $r.ServiceType) &nbsp;/&nbsp; $(HtmlEncode $r.ServiceName)</div>" +
            "<div class=`"crit-status`">$(HtmlEncode $r.OverallStatus) &mdash; Service: $(HtmlEncode $r.Status)</div>" +
            "</div></div>"
    }
    $criticalSummaryHtml = "<div class=`"crit-banner`"><div class=`"crit-banner-title`">&#9888; $($critRows.Count) Critical / Down Issue(s)</div><div class=`"crit-cards`">$cards</div></div>"
}

$htmlContent = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
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
  .stat-card.ok .stat-num { color: #3fb950; }
  .stat-card.warn .stat-num { color: #d29922; }
  .stat-card.crit .stat-num { color: #e07b00; }
  .stat-card.down .stat-num { color: #e07b00; }
  .stat-card.total .stat-num { color: #79c0ff; }
  .zone-pills { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 20px; }
  .zone-pill { display: inline-flex; align-items: center; gap: 8px; padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 600; border: 1px solid transparent; }
  .zone-pill .pill-name { color: #e6edf3; }
  .zone-pill .pill-counts { font-size: 11px; opacity: 0.8; }
  .zone-pill.ok   { background: #0d1f12; border-color: #238636; }
  .zone-pill.warn { background: #1f1a0d; border-color: #9e6a03; }
  .zone-pill.crit { background: #1c1100; border-color: #c76b00; }
  .crit-banner { background: #1c1100; border: 2px solid #c76b00; border-radius: 10px; padding: 16px 20px; margin-bottom: 20px; }
  .crit-banner-title { font-size: 13px; font-weight: 800; color: #ff9500; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 12px; }
  .crit-cards { display: flex; flex-wrap: wrap; gap: 10px; }
  .crit-card { background: #130c00; border: 1px solid #c76b00; border-radius: 8px; padding: 10px 14px; display: flex; align-items: flex-start; gap: 10px; min-width: 260px; flex: 1 1 260px; }
  .crit-icon { font-size: 20px; color: #ff9500; line-height: 1; flex-shrink: 0; margin-top: 2px; }
  .crit-body { display: flex; flex-direction: column

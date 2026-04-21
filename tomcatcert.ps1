# Remote Service Status Checker (Parallel with Logging)
# Checks Tomcat, Content Server, and Content Server Admin on remote Windows servers

#region Parameters
param(
    [switch]$QuietOK,
    [switch]$SkipCredentialPrompt,
    [string]$SmtpServer   = "smtp.domain.com",
    [string]$EmailFrom    = "monitoring@domain.com",
    [string]$EmailTo      = "ops@domain.com",
    [int]$InformantWarnMs = 5000
)
#endregion

#region Configuration
$configFile = Join-Path $PSScriptRoot "servers.txt"
if (-not (Test-Path $configFile)) {
    Write-Host "ERROR: Server config file not found: $configFile" -ForegroundColor Red
    Write-Host "Create a servers.txt file in the same directory as this script," -ForegroundColor Yellow
    Write-Host "with one server FQDN per line. Lines starting with # are treated as comments." -ForegroundColor Yellow
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

$timestamp         = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile           = Join-Path $PSScriptRoot ("ServiceCheck_" + $timestamp + ".log")
$csvFile           = Join-Path $PSScriptRoot ("ServiceCheck_" + $timestamp + ".csv")
$htmlFile          = Join-Path $PSScriptRoot ("ServiceCheck_" + $timestamp + ".html")
$prevCsvPattern    = Join-Path $PSScriptRoot "ServiceCheck_*.csv"
$maxParallelJobs   = 5
$webTimeoutSec     = 45
$cpuSampleCount    = 5
$cpuSampleDelaySec = 3
$jobTimeoutSec     = 300
$eventLogCount     = 5
$portCheckTimeout  = 3
#endregion

#region Helpers
function Write-Log {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
    Add-Content -Path $logFile -Value $Message
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
#endregion

#region Script Block
$checkServicesScript = {
    param(
        [string]$ComputerName,
        [string]$GroupName,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$WebTimeoutSec,
        [int]$InformantWarnMs,
        [int]$CpuSampleCount,
        [int]$CpuSampleDelaySec,
        [int]$EventLogCount,
        [int]$PortCheckTimeout
    )

    # ── Inline helpers ────────────────────────────────────────────────────────
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

    $scHost = $ComputerName -replace "\..*", ""

    function Get-RestartConfig {
        param([string]$ServiceName)
        $info  = sc.exe "\\$scHost" qfailure $ServiceName 2>&1
        $count = ($info | Select-String "RESTART" | Measure-Object).Count
        if ($count -eq 0)  { return "Not configured [WARN - expected 3]" }
        if ($count -ne 3)  { return "$count restart action(s) configured [WARN - expected 3]" }
        return "3 restart action(s) configured [OK]"
    }

    function Get-OrSet-RestartConfig {
        param([string]$ServiceName)
        $info  = sc.exe "\\$scHost" qfailure $ServiceName 2>&1
        $count = ($info | Select-String "RESTART" | Measure-Object).Count

        if ($count -ne 3) {
            # Log the pre-fix state then apply correction
            $priorState = if ($count -eq 0) { "Not configured" } else { "$count restart action(s) configured" }
            $fix = sc.exe "\\$scHost" failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 2>&1

            if ($LASTEXITCODE -eq 0) {
                # Re-query to confirm final state
                $verify = sc.exe "\\$scHost" qfailure $ServiceName 2>&1
                $finalCount = ($verify | Select-String "RESTART" | Measure-Object).Count
                return [PSCustomObject]@{
                    LogNote  = "Restart config updated on $ServiceName - was: $priorState"
                    Display  = "$finalCount restart action(s) configured [OK]"
                }
            } else {
                return [PSCustomObject]@{
                    LogNote  = "Failed to update restart config on $ServiceName - was: $priorState - error: $fix"
                    Display  = "$priorState [ERROR - update failed]"
                }
            }
        }

        return [PSCustomObject]@{ LogNote = $null; Display = "3 restart action(s) configured [OK]" }
    }

    function Get-ServiceRestartCount {
        param([string]$ServiceName)
        try {
            $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
                LogName   = "System"
                Id        = @(7034, 7036)
                StartTime = (Get-Date).AddDays(-1)
            } -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -like "*$ServiceName*" }
            return if ($events) { $events.Count } else { 0 }
        } catch { return "N/A" }
    }

    function Get-VisualBar {
        param([double]$Pct, [int]$W = 20)
        $f = [math]::Round($Pct / (100 / $W))
        return ("[" + ("#" * $f).PadRight($W, "-") + "]")
    }

    function Get-ThresholdTag {
        param([double]$Pct)
        if ($Pct -ge 90) { return " [CRITICAL]" } elseif ($Pct -ge 75) { return " [WARN]" } else { return "" }
    }

    function Add-ResourceBlock {
        param($List, [double]$CpuPct, [int]$SampleCount)
        $List.Add("")
        $List.Add("  --- System Resources ---")
        $bar = Get-VisualBar -Pct $CpuPct
        $tag = Get-ThresholdTag -Pct $CpuPct
        $List.Add("  CPU Usage : $bar $CpuPct% (avg over $SampleCount samples)$tag")
    }

    # ── Parallel Informant health checks ─────────────────────────────────────
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
                $results[$comp] = [PSCustomObject]@{ Content = $null; Ms = ($TimeoutSec * 1000); Error = "Timed out" }
            }
        }
        return $results
    }

    $instanceResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ── Ping ──────────────────────────────────────────────────────────────────
    $pingOk = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (-not $pingOk) {
        $out = [System.Collections.Generic.List[string]]::new()
        $out.Add(""); $out.Add("========================================")
        $out.Add("Zone     : $GroupName"); $out.Add("Server   : $ComputerName")
        $out.Add("Instance : N/A (host unreachable)")
        $out.Add("  ERROR: Host unreachable (no ping response) - skipping.")
        $out.Add("========================================")
        $instanceResults.Add([PSCustomObject]@{
            ComputerName  = $ComputerName; GroupName = $GroupName
            InstanceLabel = "N/A"; Output = $out; CsvRows = $null
            OverallStatus = "DOWN"
        })
        return $instanceResults
    }

    # ── CIM session ───────────────────────────────────────────────────────────
    $cimParams = @{ ComputerName = $ComputerName; ErrorAction = "Stop" }
    if ($Credential) { $cimParams["Credential"] = $Credential }
    try { $session = New-CimSession @cimParams }
    catch {
        $out = [System.Collections.Generic.List[string]]::new()
        $out.Add(""); $out.Add("========================================")
        $out.Add("Zone     : $GroupName"); $out.Add("Server   : $ComputerName")
        $out.Add("Instance : N/A (CIM session failed)")
        $out.Add("  ERROR: Could not open CIM session - $_")
        $out.Add("========================================")
        $instanceResults.Add([PSCustomObject]@{
            ComputerName  = $ComputerName; GroupName = $GroupName
            InstanceLabel = "N/A"; Output = $out; CsvRows = $null
            OverallStatus = "DOWN"
        })
        return $instanceResults
    }

    # ── System-wide data ──────────────────────────────────────────────────────
    $os         = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -ErrorAction Stop
    $allCimSvcs = Get-CimInstance -CimSession $session -ClassName Win32_Service         -ErrorAction Stop
    $allDisks   = Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk `
                      -Filter "DriveType=3" -ErrorAction SilentlyContinue | Sort-Object DeviceID

    $cpuSamples = @()
    for ($i = 1; $i -le $CpuSampleCount; $i++) {
        $cpuSamples += (Get-CimInstance -CimSession $session -ClassName Win32_Processor -ErrorAction Stop |
                        Measure-Object -Property LoadPercentage -Average).Average
        if ($i -lt $CpuSampleCount) { Start-Sleep -Seconds $CpuSampleDelaySec }
    }
    $cpuAvg = [math]::Round(($cpuSamples | Measure-Object -Average).Average, 1)

    $totalMemGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeMemGB  = [math]::Round($os.FreePhysicalMemory      / 1MB, 2)
    $usedMemGB  = [math]::Round($totalMemGB - $freeMemGB, 2)
    $memPct     = if ($totalMemGB -gt 0) { [math]::Round(($usedMemGB / $totalMemGB) * 100, 1) } else { 0 }
    $memBar     = Get-VisualBar -Pct $memPct
    $memTag     = Get-ThresholdTag -Pct $memPct

    $uptimeStr  = Get-UptimeString -LastBootTime $os.LastBootUpTime
    $recentTag  = if (((Get-Date) - $os.LastBootUpTime).TotalHours -lt 24) { "  [WARN - Recent Reboot]" } else { "" }

    $drivesSummaryForCsv = ($allDisks | ForEach-Object {
        $t = [math]::Round($_.Size / 1GB, 2); $f = [math]::Round($_.FreeSpace / 1GB, 2)
        $u = [math]::Round($t - $f, 2)
        $p = if ($t -gt 0) { [math]::Round(($u / $t) * 100, 1) } else { 0 }
        ($_.DeviceID + " " + $p + "% (" + $u + "/" + $t + " GB)")
    }) -join " | "

    $driveSummary = if ($allDisks) {
        ($allDisks | ForEach-Object {
            $totGB  = [math]::Round($_.Size / 1GB, 2); $freeGB = [math]::Round($_.FreeSpace / 1GB, 2)
            $usedGB = [math]::Round($totGB - $freeGB, 2)
            $pct    = if ($totGB -gt 0) { [math]::Round(($usedGB / $totGB) * 100, 1) } else { 0 }
            $bar    = Get-VisualBar -Pct $pct; $tag = Get-ThresholdTag -Pct $pct
            ("    " + $_.DeviceID + "  " + $bar + " " + $pct + "% used  (" + $usedGB + " GB / " + $totGB + " GB)  Free: " + $freeGB + " GB" + $tag)
        }) -join "`n"
    } else { "    No fixed drives found." }

    # ── Event log scan ────────────────────────────────────────────────────────
    $recentEvents = @()
    try {
        $recentEvents = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
            LogName   = "Application"
            Level     = @(1, 2, 3)
            StartTime = (Get-Date).AddHours(-24)
        } -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match "Tomcat|catalina|Content Server" } |
        Select-Object -First $EventLogCount
    } catch { }

    # ── Locate services ───────────────────────────────────────────────────────
    $tomcatSvc = $allCimSvcs | Where-Object {
        $_.DisplayName -like "*Apache*Tomcat*" -or $_.Name -like "*Tomcat*"
    } | Select-Object -First 1

    $csSvcs = @($allCimSvcs | Where-Object {
        $_.Description -like "*Content Server*" -and $_.Description -notlike "*Content Server Admin*"
    })

    $csAdmin = $allCimSvcs | Where-Object {
        $_.Description -like "*Content Server Admin*"
    } | Select-Object -First 1

    # ── Port check (port 80 only) ─────────────────────────────────────────────
    $port80ok   = $false
    $port80text = "N/A"
    if ($tomcatSvc) {
        $tc         = Test-NetConnection -ComputerName $ComputerName -Port 80 `
                          -WarningAction SilentlyContinue -InformationLevel Quiet
        $port80ok   = $tc.TcpTestSucceeded
        $port80text = if ($port80ok) { "[OPEN]" } else { "[CLOSED]" }
    }

    # ── Tomcat version ────────────────────────────────────────────────────────
    $tomcatVersion = "N/A"
    if ($tomcatSvc) {
        $icParams = @{
            ComputerName = $ComputerName; ErrorAction = "Stop"
            ArgumentList = $tomcatSvc.Name, $tomcatSvc.PathName
            ScriptBlock  = {
                param([string]$SvcName, [string]$ImagePath)
                $tomcatHome = $null; $tomcatVersion = "Unknown"
                $regPaths = @(
                    ("HKLM:\SOFTWARE\Apache Software Foundation\Procrun 2.0\" + $SvcName + "\Parameters\Java"),
                    ("HKLM:\SOFTWARE\WOW6432Node\Apache Software Foundation\Procrun 2.0\" + $SvcName + "\Parameters\Java")
                )
                foreach ($reg in $regPaths) {
                    if (Test-Path $reg) {
                        $cp = (Get-ItemProperty $reg -ErrorAction SilentlyContinue).Classpath
                        if ($cp -match "^(.+?)\\lib\\") { $tomcatHome = $Matches[1]; break }
                    }
                }
                if (-not $tomcatHome) {
                    $cat = [System.Environment]::GetEnvironmentVariable("CATALINA_HOME", "Machine")
                    if ($cat -and (Test-Path $cat)) { $tomcatHome = $cat }
                }
                if (-not $tomcatHome) {
                    if ($ImagePath -match ("^" + [char]34 + "?([^" + [char]34 + "]+\.exe)" + [char]34 + "?")) {
                        $exeDir = Split-Path $Matches[1] -Parent
                        foreach ($candidate in @((Split-Path $exeDir -Parent), $exeDir)) {
                            if (Test-Path (Join-Path $candidate "lib")) { $tomcatHome = $candidate; break }
                        }
                    }
                }
                if ($tomcatHome) {
                    foreach ($f in @("RELEASE-NOTES", "RUNNING.txt")) {
                        $fp = Join-Path $tomcatHome $f
                        if (Test-Path $fp) {
                            $content = Get-Content $fp -TotalCount 15 -ErrorAction SilentlyContinue
                            foreach ($ln in $content) {
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
                                    $reader  = New-Object System.IO.StreamReader($entry.Open())
                                    $content = $reader.ReadToEnd(); $reader.Close()
                                    if ($content -match "Implementation-Version:\s*([0-9]+\.[0-9]+\.[0-9]+)") {
                                        $tomcatVersion = $Matches[1].Trim()
                                    }
                                }
                                $z.Dispose()
                            } catch {}
                        }
                    }
                }
                return $tomcatVersion
            }
        }
        if ($Credential) { $icParams["Credential"] = $Credential }
        $tomcatVersion = try { Invoke-Command @icParams } catch { "Unable to retrieve" }
    }

    # ── JVM heap via Win32_Process working set (JMX not available) ───────────
    $wsMB          = $null
    $jvmHeapText   = "N/A"
    $jvmHeapCsvStr = "N/A"
    if ($tomcatSvc -and $tomcatSvc.State -eq "Running") {
        $wsMB = Get-ProcessMemoryMB -CimSession $session -ProcessId $tomcatSvc.ProcessId
        if ($wsMB) {
            $jvmHeapText   = "Working Set: ${wsMB} MB"
            $jvmHeapCsvStr = "${wsMB} MB"
        }
    }

    # ── Build output ──────────────────────────────────────────────────────────
    $checkTime     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $csvRows       = [System.Collections.Generic.List[PSCustomObject]]::new()
    $overallStatus = "OK"

    $driveCritical = $allDisks | Where-Object {
        $t = $_.Size; $f = $_.FreeSpace
        if ($t -gt 0) { (($t - $f) / $t * 100) -ge 90 } else { $false }
    }
    if ($driveCritical)   { $overallStatus = "CRITICAL" }
    if ($memPct -ge 90)   { $overallStatus = "CRITICAL" }
    if ($cpuAvg -ge 90)   { if ($overallStatus -ne "CRITICAL") { $overallStatus = "WARN" } }
    if ($memPct -ge 75)   { if ($overallStatus -eq "OK") { $overallStatus = "WARN" } }
    if ($recentTag -ne "") { if ($overallStatus -eq "OK") { $overallStatus = "WARN" } }

    $out = [System.Collections.Generic.List[string]]::new()
    $out.Add(""); $out.Add("========================================")
    $out.Add("Zone     : $GroupName")
    $out.Add("Server   : $ComputerName")
    $out.Add("  Server Uptime: $uptimeStr$recentTag")
    $out.Add("  Memory       : $memBar $memPct% used  ($usedMemGB GB / $totalMemGB GB)  Free: $freeMemGB GB$memTag")
    $out.Add("  Drives:")
    foreach ($dline in ($driveSummary -split "`n")) {
        if ($dline -match "\[CRITICAL\]") { $out.Add("[DRIVE_CRITICAL] $dline") } else { $out.Add($dline) }
    }
    $out.Add("========================================")

    # ── Tomcat ────────────────────────────────────────────────────────────────
    $out.Add(""); $out.Add("Tomcat Service:")
    if ($tomcatSvc) {
        $tState        = if ($tomcatSvc.State -eq "Running") { "[RUNNING]" } else { "[STOPPED]" }
        $tUp           = Get-ServiceUptime    -CimSession $session -ProcessId $tomcatSvc.ProcessId
        $tRestartResult = Get-OrSet-RestartConfig -ServiceName $tomcatSvc.Name
        if ($tRestartResult.LogNote) { $out.Add("  [LOG] $($tRestartResult.LogNote)") }
        $tRestart = $tRestartResult.Display
        $tRestartCount = Get-ServiceRestartCount -ServiceName $tomcatSvc.Name
        if ($tomcatSvc.State -ne "Running") { $overallStatus = "DOWN" }

        $out.Add("  Name:               $($tomcatSvc.Name)")
        $out.Add("  Status:             $tState")
        $out.Add("  Display Name:       $($tomcatSvc.DisplayName)")
        $out.Add("  Version:            $tomcatVersion")
        $out.Add("  Run As:             $($tomcatSvc.StartName)")
        $out.Add("  Service Uptime:     $tUp")
        $out.Add("  Restart Config:     $tRestart")
        $out.Add("  Auto-Restarts(24h): $tRestartCount")
        $out.Add("  Working Set:        $jvmHeapText")
        $out.Add("  Port 80:            $port80text")

        if (-not $port80ok -and $tomcatSvc.State -eq "Running") {
            if ($overallStatus -eq "OK") { $overallStatus = "WARN" }
        }

        $csvRows.Add([PSCustomObject]@{
            DateTime        = $checkTime; Zone = $GroupName; Server = $ComputerName
            ServiceType     = "Tomcat"; ServiceName = $tomcatSvc.Name
            DisplayName     = $tomcatSvc.DisplayName; Description = ""
            Status          = $tomcatSvc.State; Version = $tomcatVersion
            RunAs           = $tomcatSvc.StartName; ServiceUptime = $tUp
            RestartConfig   = $tRestart; AutoRestarts = $tRestartCount
            WorkingSetMB    = $jvmHeapCsvStr; Port80 = if ($port80ok) { "OPEN" } else { "CLOSED" }
            ServerUptime    = $uptimeStr; RecentReboot = ($recentTag -ne "")
            CpuPct          = $cpuAvg; MemPct = $memPct; MemUsedGB = $usedMemGB
            MemTotalGB      = $totalMemGB; MemFreeGB = $freeMemGB
            DrivesSummary   = $drivesSummaryForCsv; OverallStatus = $overallStatus
        })
    } else { $out.Add("  NOT FOUND") }

    # ── Content Server(s) ─────────────────────────────────────────────────────
    $out.Add(""); $out.Add("Content Server Service(s):")
    if ($csSvcs) {
        foreach ($cs in $csSvcs) {
            $csState        = if ($cs.State -eq "Running") { "[RUNNING]" } else { "[STOPPED]" }
            $csUp           = Get-ServiceUptime    -CimSession $session -ProcessId $cs.ProcessId
            $csRestartResult = Get-OrSet-RestartConfig -ServiceName $cs.Name
            if ($csRestartResult.LogNote) { $out.Add("  [LOG] $($csRestartResult.LogNote)") }
            $csRestart = $csRestartResult.Display
            $csRestartCount = Get-ServiceRestartCount -ServiceName $cs.Name
            if ($cs.State -ne "Running") { $overallStatus = "DOWN" }

            $out.Add("")
            $out.Add("  Instance:           $($cs.Name)")
            $out.Add("  Status:             $csState")
            $out.Add("  Display Name:       $($cs.DisplayName)")
            $out.Add("  Description:        $($cs.Description)")
            $out.Add("  Run As:             $($cs.StartName)")
            $out.Add("  Service Uptime:     $csUp")
            $out.Add("  Restart Config:     $csRestart")
            $out.Add("  Auto-Restarts(24h): $csRestartCount")

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
                    } else {
                        $tag = if ($ir.Content -match "=\s*success") { "[SUCCESS]" }
                               elseif ($ir.Content -match "=\s*failure") { "[FAILURE]" }
                               else { "[OTHER] - $($ir.Content)" }
                        if ($ir.Content -match "=\s*failure") { $overallStatus = "CRITICAL" }
                        $out.Add("    $comp : $tag $msLabel$slowTag")
                    }
                }
                Add-ResourceBlock -List $out -CpuPct $cpuAvg -SampleCount $CpuSampleCount
            }

            $csvRows.Add([PSCustomObject]@{
                DateTime        = $checkTime; Zone = $GroupName; Server = $ComputerName
                ServiceType     = "ContentServer"; ServiceName = $cs.Name
                DisplayName     = $cs.DisplayName; Description = $cs.Description
                Status          = $cs.State; Version = ""; RunAs = $cs.StartName
                ServiceUptime   = $csUp; RestartConfig = $csRestart; AutoRestarts = $csRestartCount
                WorkingSetMB    = "N/A"; Port80 = "N/A"
                ServerUptime    = $uptimeStr; RecentReboot = ($recentTag -ne "")
                CpuPct          = $cpuAvg; MemPct = $memPct; MemUsedGB = $usedMemGB
                MemTotalGB      = $totalMemGB; MemFreeGB = $freeMemGB
                DrivesSummary   = $drivesSummaryForCsv; OverallStatus = $overallStatus
            })
        }
    } else { $out.Add("  NOT FOUND") }

    # ── Content Server Admin ──────────────────────────────────────────────────
    $out.Add(""); $out.Add("Content Server Admin Service:")
    if ($csAdmin) {
        $caState        = if ($csAdmin.State -eq "Running") { "[RUNNING]" } else { "[STOPPED]" }
        $caUp           = Get-ServiceUptime    -CimSession $session -ProcessId $csAdmin.ProcessId
        $caRestartResult = Get-OrSet-RestartConfig -ServiceName $csAdmin.Name
        if ($caRestartResult.LogNote) { $out.Add("  [LOG] $($caRestartResult.LogNote)") }
        $caRestart = $caRestartResult.Display
        $caRestartCount = Get-ServiceRestartCount -ServiceName $csAdmin.Name
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
            DateTime        = $checkTime; Zone = $GroupName; Server = $ComputerName
            ServiceType     = "ContentServerAdmin"; ServiceName = $csAdmin.Name
            DisplayName     = $csAdmin.DisplayName; Description = $csAdmin.Description
            Status          = $csAdmin.State; Version = ""; RunAs = $csAdmin.StartName
            ServiceUptime   = $caUp; RestartConfig = $caRestart; AutoRestarts = $caRestartCount
            WorkingSetMB    = "N/A"; Port80 = "N/A"
            ServerUptime    = $uptimeStr; RecentReboot = ($recentTag -ne "")
            CpuPct          = $cpuAvg; MemPct = $memPct; MemUsedGB = $usedMemGB
            MemTotalGB      = $totalMemGB; MemFreeGB = $freeMemGB
            DrivesSummary   = $drivesSummaryForCsv; OverallStatus = $overallStatus
        })
    } else { $out.Add("  NOT FOUND") }

    # ── Recent event log entries ──────────────────────────────────────────────
    if ($recentEvents) {
        $out.Add(""); $out.Add("Recent Application Log Events (last 24h, Tomcat/CS related):")
        foreach ($ev in $recentEvents) {
            $lvl = switch ($ev.Level) { 1 {"CRITICAL"} 2 {"ERROR"} 3 {"WARN"} default {"INFO"} }
            $msg = ($ev.Message -split "`n")[0].Trim()
            if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) + "..." }
            $out.Add("  [$lvl] $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))  $($ev.ProviderName): $msg")
        }
        if ($overallStatus -eq "OK") { $overallStatus = "WARN" }
    }

    Remove-CimSession $session -ErrorAction SilentlyContinue

    $instanceResults.Add([PSCustomObject]@{
        ComputerName  = $ComputerName; GroupName = $GroupName
        InstanceLabel = $ComputerName; Output = $out; CsvRows = $csvRows
        OverallStatus = $overallStatus; TomcatVersion = $tomcatVersion
    })
    return $instanceResults
}
#endregion

#region Main

# ── Credential prompt (skipped in non-interactive / remote sessions) ──────────
$Credential = $null
$useCreds   = ""

if (-not $SkipCredentialPrompt) {
    # Probe for an interactive console before attempting KeyAvailable
    $hasConsole = $true
    try { [void][System.Console]::KeyAvailable } catch { $hasConsole = $false }

    if ($hasConsole) {
        Write-Host "Use alternate credentials? (y/n)  [auto-skipping in 10 seconds]" -ForegroundColor Cyan
        $deadline = (Get-Date).AddSeconds(10)
        while ((Get-Date) -lt $deadline) {
            try {
                if ([System.Console]::KeyAvailable) {
                    $key      = [System.Console]::ReadKey($true)
                    $useCreds = $key.KeyChar.ToString().ToLower()
                    Write-Host $useCreds
                    break
                }
            } catch { break }
            Start-Sleep -Milliseconds 100
        }
        if ($useCreds -eq "y") { $Credential = Get-Credential -Message "Enter credentials for remote servers" }
    } else {
        Write-Host "Non-interactive mode detected - skipping credential prompt." -ForegroundColor Gray
    }
} else {
    Write-Host "Credential prompt skipped (-SkipCredentialPrompt)." -ForegroundColor Gray
}

$startTime = Get-Date
Write-Log "Remote Service Status Check" -Color Cyan
Write-Log "Started: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Gray
Write-Log "Log file: $logFile" -Color Gray
Write-Log ""

# ── Start parallel jobs ───────────────────────────────────────────────────────
$jobs = [System.Collections.Generic.List[hashtable]]::new()
foreach ($group in $serverGroups.Keys) {
    foreach ($server in $serverGroups[$group]) {
        while ((Get-Job -State Running).Count -ge $maxParallelJobs) { Start-Sleep -Milliseconds 500 }
        $j = Start-Job -ScriptBlock $checkServicesScript `
                 -ArgumentList $server, $group, $Credential, $webTimeoutSec, $InformantWarnMs,
                               $cpuSampleCount, $cpuSampleDelaySec, $eventLogCount, $portCheckTimeout
        $jobs.Add(@{ Job = $j; Server = $server; Group = $group })
        Write-Log "Queued: [$group] $server" -Color Gray
    }
}

Write-Log "Checking $serverCount server(s) in parallel..." -Color Yellow

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

# ── Delta / change detection ──────────────────────────────────────────────────
$prevData = @{}
$prevCsvs = Get-ChildItem -Path $PSScriptRoot -Filter "ServiceCheck_*.csv" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne (Split-Path $csvFile -Leaf) } |
            Sort-Object LastWriteTime -Descending
if ($prevCsvs) {
    $prevRows = Import-Csv -Path $prevCsvs[0].FullName -ErrorAction SilentlyContinue
    foreach ($row in $prevRows) {
        $key = "$($row.Server)|$($row.ServiceName)"
        $prevData[$key] = $row
    }
    Write-Log "Comparing against previous run: $($prevCsvs[0].Name)" -Color Gray
}

# ── Output grouped results ────────────────────────────────────────────────────
$prevGroup   = $null
$zoneSummary = [ordered]@{}
$allVersions = @{}

foreach ($result in ($results | Sort-Object GroupName, ComputerName)) {
    $grp = $result.GroupName
    if (-not $zoneSummary.Contains($grp)) {
        $zoneSummary[$grp] = @{ OK=0; WARN=0; DOWN=0; CRITICAL=0 }
    }
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

    $isClean  = ($result.OverallStatus -eq "OK")
    $deltaTag = ""
    if ($result.CsvRows) {
        foreach ($row in $result.CsvRows) {
            $key  = "$($row.Server)|$($row.ServiceName)"
            $prev = $prevData[$key]
            if ($prev -and ($prev.Status -ne $row.Status -or $prev.Version -ne $row.Version)) {
                $deltaTag = "  [CHANGED]"; $isClean = $false
            }
        }
    }

    if ($QuietOK -and $isClean) {
        Write-Log "  $($result.ComputerName) : OK$deltaTag" -Color Green
        continue
    }

    foreach ($line in $result.Output) {
        $color = "White"
        if     ($line -match "^={3,}|Server   :")                                                        { $color = "Cyan"    }
        elseif ($line -match "Zone     :")                                                                { $color = "Magenta" }
        elseif ($line -match "Recent Reboot")                                                             { $color = "Yellow"  }
        elseif ($line -match "Tomcat Service:|Content Server Service|Informant Health|System Resources") { $color = "Yellow"  }
        elseif ($line -match "^\[DRIVE_CRITICAL\] ") { $color = "Red"; $line = $line -replace "^\[DRIVE_CRITICAL\] ", "" }
        elseif ($line -match "\[RUNNING\]|\[SUCCESS\]")                                                  { $color = "Green"   }
        elseif ($line -match "\[STOPPED\]|ERROR:|NOT FOUND|\[FAILURE\]|\[ERROR\]|\[CRITICAL\]")         { $color = "Red"     }
        elseif ($line -match "\[WARN\]|\[OTHER\]|\[SLOW\]")                                              { $color = "Yellow"  }
        elseif ($line -match "Working Set:|Auto-Restarts|Port 80:")                                      { $color = "Cyan"    }
        elseif ($line -match "Run As:|Restart Config:|Service Uptime:|CPU|Memory|Drive")                 { $color = "Cyan"    }
        elseif ($line -match "Description:|Display Name:")                                               { $color = "Gray"    }
        Write-Log $line -Color $color
    }
    if ($deltaTag) { Write-Log "  >> Delta detected on $($result.ComputerName)$deltaTag" -Color Yellow }
}

# ── Zone-level rollup ─────────────────────────────────────────────────────────
Write-Log ""; Write-Log "======== Zone Rollup ========" -Color Cyan
foreach ($grp in $zoneSummary.Keys) {
    $s   = $zoneSummary[$grp]
    $tot = $s.OK + $s.WARN + $s.DOWN + $s.CRITICAL
    $col = if ($s.DOWN -gt 0 -or $s.CRITICAL -gt 0) { "Red" } elseif ($s.WARN -gt 0) { "Yellow" } else { "Green" }
    Write-Log ("  {0,-40} : {1} OK, {2} WARN, {3} CRITICAL, {4} DOWN  (of {5})" -f `
        $grp, $s.OK, $s.WARN, $s.CRITICAL, $s.DOWN, $tot) -Color $col

    if ($allVersions.Contains($grp) -and $allVersions[$grp].Count -gt 1) {
        $versionGroups = $allVersions[$grp].Values | Group-Object | Sort-Object Count -Descending
        $majority      = $versionGroups[0].Name
        $outliers      = $allVersions[$grp].GetEnumerator() | Where-Object { $_.Value -ne $majority }
        if ($outliers) {
            Write-Log "    [VERSION MISMATCH] Majority: $majority - outliers:" -Color Yellow
            foreach ($o in $outliers) { Write-Log "      $($o.Key) : $($o.Value)" -Color Yellow }
        }
    }
}
Write-Log "=============================" -Color Cyan

# ── CSV export ────────────────────────────────────────────────────────────────
$allCsvRows = $results | ForEach-Object { $_.CsvRows } | Where-Object { $_ }
if ($allCsvRows) {
    $allCsvRows | Sort-Object Zone, Server, ServiceType |
        Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Log "CSV saved to   : $csvFile" -Color Green
} else {
    Write-Log "No CSV data to export." -Color Yellow
}

# ── HTML report ───────────────────────────────────────────────────────────────
$htmlRows = $allCsvRows | Sort-Object Zone, Server, ServiceType

$htmlBody = ""
$htmlRows | Group-Object Zone | ForEach-Object {
    $zoneName   = $_.Name
    $zoneRows   = $_.Group
    $zoneStatus = if ($zoneRows | Where-Object { $_.OverallStatus -in @("DOWN","CRITICAL") }) { "down" }
                  elseif ($zoneRows | Where-Object { $_.OverallStatus -eq "WARN" }) { "warn" }
                  else { "ok" }
    $zoneId = $zoneName -replace '[^a-zA-Z0-9]', '_'

    $serverHtml = ""
    $zoneRows | Group-Object Server | ForEach-Object {
        $serverName   = $_.Name
        $serverRows   = $_.Group
        $serverStatus = if ($serverRows | Where-Object { $_.OverallStatus -in @("DOWN","CRITICAL") }) { "down" }
                        elseif ($serverRows | Where-Object { $_.OverallStatus -eq "WARN" }) { "warn" }
                        else { "ok" }
        $serverId = ($zoneId + "_" + ($serverName -replace '[^a-zA-Z0-9]', '_'))

        $instanceHtml = ""
        $csRows     = $serverRows | Where-Object { $_.ServiceType -eq "ContentServer" }
        $tomcatRow  = $serverRows | Where-Object { $_.ServiceType -eq "Tomcat" }             | Select-Object -First 1
        $csAdminRow = $serverRows | Where-Object { $_.ServiceType -eq "ContentServerAdmin" } | Select-Object -First 1

        $csRows | ForEach-Object {
            $primary  = $_
            $instName = $primary.ServiceName
            $tomcat   = $tomcatRow
            $csAdmin  = $csAdminRow
            $sc = switch ($primary.OverallStatus) {
                "OK" { "ok" } "WARN" { "warn" } "CRITICAL" { "critical" } "DOWN" { "down" } default { "" }
            }
            $instId = ($serverId + "_" + ($instName -replace '[^a-zA-Z0-9]', '_'))

            $instanceHtml += "
            <tr class='instance-header $sc' onclick='toggle(""$instId"")'>
              <td colspan='2' class='inst-label'>&#x25B6; Instance: <strong>$instName</strong></td>
              <td>$($primary.Status)</td>
              <td>$(if($tomcat){$tomcat.Version}else{'N/A'})</td>
              <td>$(if($tomcat){$tomcat.WorkingSetMB}else{'N/A'})</td>
              <td>$(if($tomcat){$tomcat.Port80}else{'N/A'})</td>
              <td>$($primary.CpuPct)%</td>
              <td>$($primary.MemPct)%</td>
              <td>$($primary.AutoRestarts)</td>
              <td class='status-cell'>$($primary.OverallStatus)</td>
            </tr>
            <tbody id='$instId' class='collapsible'>
              <tr class='detail-row'><td class='detail-label'>Run As</td><td colspan='9'>$($primary.RunAs)</td></tr>
              <tr class='detail-row'><td class='detail-label'>Service Uptime</td><td colspan='9'>$($primary.ServiceUptime)</td></tr>
              <tr class='detail-row'><td class='detail-label'>Restart Config</td><td colspan='9'>$($primary.RestartConfig)</td></tr>
              <tr class='detail-row'><td class='detail-label'>Drives</td><td colspan='9'>$($primary.DrivesSummary)</td></tr>
              $(if($tomcat){"<tr class='detail-row'><td class='detail-label'>Tomcat Service</td><td colspan='9'>$($tomcat.ServiceName) [$($tomcat.Status)] v$($tomcat.Version)</td></tr>"})
              $(if($csAdmin){"<tr class='detail-row'><td class='detail-label'>CS Admin</td><td colspan='9'>$($csAdmin.ServiceName) [$($csAdmin.Status)]</td></tr>"})
            </tbody>"
        }

        $serverHtml += "
        <tr class='server-header $serverStatus' onclick='toggle(""$serverId"")'>
          <td colspan='10' class='server-label'>&#x25BC; <strong>$serverName</strong></td>
        </tr>
        <tbody id='$serverId' class='collapsible'>
          <table class='inner-table'>
            <thead><tr>
              <th>Instance</th><th>Service Name</th><th>Status</th><th>Version</th>
              <th>Working Set</th><th>Port 80</th><th>CPU%</th><th>Mem%</th>
              <th>Restarts</th><th>Overall</th>
            </tr></thead>
            <tbody>$instanceHtml</tbody>
          </table>
        </tbody>"
    }

    $htmlBody += "
    <tr class='zone-header $zoneStatus' onclick='toggle(""$zoneId"")'>
      <td colspan='10' class='zone-label'>&#x25BC; Zone: <strong>$zoneName</strong></td>
    </tr>
    <tbody id='$zoneId' class='collapsible'>$serverHtml</tbody>"
}

$zoneRollupHtml = foreach ($grp in $zoneSummary.Keys) {
    $s   = $zoneSummary[$grp]
    $cls = if ($s.DOWN -gt 0 -or $s.CRITICAL -gt 0) { "down" } elseif ($s.WARN -gt 0) { "warn" } else { "ok" }
    "<div class='zone-pill $cls'>$grp &nbsp; OK:$($s.OK) WARN:$($s.WARN) CRITICAL:$($s.CRITICAL) DOWN:$($s.DOWN)</div>"
}

$html = @"
<!DOCTYPE html>
<html><head><meta charset='UTF-8'>
<title>Service Check Report - $timestamp</title>
<style>
  body{font-family:Consolas,monospace;background:#1e1e1e;color:#d4d4d4;margin:20px}
  h1{color:#4ec9b0} h2{color:#9cdcfe}
  table{border-collapse:collapse;width:100%;margin-top:10px}
  .inner-table{width:100%;border-collapse:collapse;margin:0}
  th{background:#2d2d2d;color:#9cdcfe;padding:6px 10px;text-align:left;border:1px solid #3c3c3c}
  td{padding:5px 10px;border:1px solid #3c3c3c;font-size:12px}
  .zone-header td{background:#1a3a5c;color:#9cdcfe;font-size:14px;cursor:pointer;padding:8px 12px}
  .server-header td{background:#252540;color:#c586c0;font-size:13px;cursor:pointer;padding:6px 20px}
  .instance-header td{cursor:pointer}
  .zone-label,.server-label,.inst-label{user-select:none}
  .zone-header.ok td{border-left:4px solid #4ec9b0}
  .zone-header.warn td{border-left:4px solid #dcdcaa}
  .zone-header.down td,.zone-header.critical td{border-left:4px solid #f44747}
  .server-header.ok td{border-left:4px solid #4ec9b0}
  .server-header.warn td{border-left:4px solid #dcdcaa}
  .server-header.down td,.server-header.critical td{border-left:4px solid #f44747}
  tr.ok td{color:#4ec9b0} tr.warn td{color:#dcdcaa} tr.critical td{color:#f44747} tr.down td{color:#f44747;font-weight:bold}
  .detail-row td{background:#1a1a1a;font-size:11px;color:#9a9a9a;padding:3px 10px 3px 30px}
  .detail-label{color:#569cd6;width:130px;font-weight:bold}
  tr:hover td{background:#2a2d2e}
  .collapsible{display:table-row-group}
  .zone-pill{display:inline-block;margin:4px 6px;padding:6px 14px;border-radius:14px;font-size:13px;font-weight:bold}
  .zone-pill.ok{background:#1e3a2f;color:#4ec9b0;border:1px solid #4ec9b0}
  .zone-pill.warn{background:#3a3000;color:#dcdcaa;border:1px solid #dcdcaa}
  .zone-pill.critical,.zone-pill.down{background:#3a1e1e;color:#f44747;border:1px solid #f44747}
  .summary{background:#252526;padding:12px;border-radius:6px;margin-bottom:18px}
</style></head><body>
<h1>&#x1F4CA; Service Check Report</h1>
<div class='summary'><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp; <strong>Servers checked:</strong> $serverCount</div>
<h2>Zone Summary</h2>
<div>$($zoneRollupHtml -join '')</div>
<h2>Detail</h2>
<table id='main-table'>
<thead><tr><th colspan='10'>Zone / Server / Instance</th></tr></thead>
<tbody>$htmlBody</tbody>
</table>
<script>
function toggle(id){
  var el=document.getElementById(id);
  if(el){el.style.display=(el.style.display==='none'?'':'none');}
}
</script>
</body></html>
"@
$html | Out-File -FilePath $htmlFile -Encoding UTF8
Write-Log "HTML report    : $htmlFile" -Color Green

# ── Email on issues ───────────────────────────────────────────────────────────
$issueRows = $allCsvRows | Where-Object { $_.OverallStatus -in @("DOWN","CRITICAL") }
if ($issueRows) {
    $bodyLines = @("Service Check Alert - $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))", "")
    foreach ($r in $issueRows) {
        $bodyLines += "[$($r.OverallStatus)] $($r.Zone) / $($r.Server) - $($r.ServiceType) ($($r.ServiceName)): $($r.Status)"
    }
    try {
        Send-MailMessage -SmtpServer $SmtpServer -From $EmailFrom -To $EmailTo `
            -Subject "Service Check Alert: $($issueRows.Count) issue(s) detected" `
            -Body ($bodyLines -join "`n") -ErrorAction Stop
        Write-Log "Alert email sent to $EmailTo" -Color Green
    } catch {
        Write-Log "Failed to send alert email: $_" -Color Red
    }
}

# ── Footer ────────────────────────────────────────────────────────────────────
$endTime = Get-Date; $dur = $endTime - $startTime
Write-Log ""
Write-Log "========================================" -Color Cyan
Write-Log "Completed: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Cyan
Write-Log "Duration:  $($dur.ToString('mm\:ss'))" -Color Cyan
Write-Log "========================================" -Color Cyan
Write-Log "Log  : $logFile" -Color Green
Write-Log "CSV  : $csvFile" -Color Green
Write-Log "HTML : $htmlFile" -Color Green
#endregion

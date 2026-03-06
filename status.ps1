#Requires -Version 5.1
# Remote Service Status Checker (Parallel with Logging)
# Checks Tomcat, Content Server, and Content Server Admin on remote Windows servers
# v4.0 -- redesigned HTML report

#region Parameters
param(
    [switch]$QuietOK,
    [string]$SmtpServer      = "smtp.domain.com",
    [string]$EmailFrom       = "monitoring@domain.com",
    [string]$EmailTo         = "ops@domain.com",
    [string]$TeamsWebhookUrl = "",
    [switch]$AutoRestartStopped,
    [int]$InformantWarnMs    = 5000,
    [int]$MaxParallelJobs    = 10
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
            ComputerName = $ComputerName; GroupName     = $GroupName
            InstanceLabel = "N/A";        Output        = $out;       CsvRows       = $null
            OverallStatus = "DOWN";       TomcatVersion = $null
            EventLines    = @();          DriveErrors   = @();        DriveWarnings = @()
            InformantResults = @{};       GcCollector   = "N/A"
            GcWarnings    = @();          GcRecommend   = @()
            MemPct        = 0;            CpuAvg        = 0
            MemUsedGB     = 0;            MemTotalGB    = 0;          MemFreeGB     = 0
            DrivesSummary = "";           Uptime        = "N/A";      JobLog        = $jobLog
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
            ComputerName = $ComputerName; GroupName     = $GroupName
            InstanceLabel = "N/A";        Output        = $out;       CsvRows       = $null
            OverallStatus = "DOWN";       TomcatVersion = $null
            EventLines    = @();          DriveErrors   = @();        DriveWarnings = @()
            InformantResults = @{};       GcCollector   = "N/A"
            GcWarnings    = @();          GcRecommend   = @()
            MemPct        = 0;            CpuAvg        = 0
            MemUsedGB     = 0;            MemTotalGB    = 0;          MemFreeGB     = 0
            DrivesSummary = "";           Uptime        = "N/A";      JobLog        = $jobLog
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
            $prefix = if ($pct -ge 90) { "[DRIVE_CRITICAL] " } else { "" }
            ($prefix + "    " + $_.DeviceID + "  " + (Get-VisualBar -Pct $pct) + " " + $pct +
             "% used  (" + $usedGB + " GB / " + $totGB + " GB)  Free: " + $freeGB + " GB" +
             (Get-ThresholdTag -Pct $pct))
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
                        $jrePath   = if (Test-Path (Join-Path $candidate "bin\java.exe")) {
                                         $candidate
                                     } else { Split-Path $jvmDll -Parent }
                    }
                    if ($regProps.Options) {
                        $optFlat = if ($regProps.Options -is [array]) {
                            $regProps.Options -join ' '
                        } else { [string]$regProps.Options }
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
                } elseif (-not $jcmdPath)    { $gcCollector = "jcmd not found (JRE-only install?)" }
                  elseif ($ProcessId -le 0)  { $gcCollector = "N/A (service not running)" }

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
                    Version     = $tomcatVersion; JrePath     = $jrePath
                    HeapInitMB  = $heapInitMB;    HeapMaxMB   = $heapMaxMB
                    GcCollector = $gcCollector;   GcWarnings  = $gcWarnings
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
    if ($driveErrors.Count -gt 0)   { $out.Add("  [ERROR] Drive critical: " + ($driveErrors -join "; ")) }
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
            DateTime      = $checkTime;          Zone          = $GroupName
            Server        = $ComputerName;        ServiceType   = "Tomcat"
            ServiceName   = $tomcatSvc.Name;      DisplayName   = $tomcatSvc.DisplayName
            Description   = "";                   Status        = $tomcatSvc.State
            Version       = $tomcatVersion;        JrePath       = $jrePath
            HeapInitMB    = $heapInitMB;           HeapMaxMB     = $heapMaxMB
            GcCollector   = $gcCollector;          GcWarnings    = ($gcWarnings  -join " | ")
            GcRecommend   = ($gcRecommend -join " | ")
            RunAs         = $tomcatSvc.StartName;  ServiceUptime = $tUp
            RestartConfig = $tRestart;             AutoRestarts  = $tRestartCount
            WorkingSetMB  = $jvmHeapCsvStr;        ServerUptime  = $uptimeStr
            RecentReboot  = ($recentTag -ne "");   CpuPct        = $cpuAvg
            MemPct        = $memPct;               MemUsedGB     = $usedMemGB
            MemTotalGB    = $totalMemGB;            MemFreeGB     = $freeMemGB
            DrivesSummary = $drivesSummaryForCsv;  OverallStatus = $overallStatus
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
                DateTime      = $checkTime;         Zone          = $GroupName
                Server        = $ComputerName;       ServiceType   = "ContentServer"
                ServiceName   = $cs.Name;            DisplayName   = $cs.DisplayName
                Description   = $cs.Description;     Status        = $cs.State
                Version       = "";                  JrePath       = ""
                HeapInitMB    = $null;               HeapMaxMB     = $null
                GcCollector   = "";                  GcWarnings    = "";             GcRecommend = ""
                RunAs         = $cs.StartName;       ServiceUptime = $csUp
                RestartConfig = $csRestart;          AutoRestarts  = $csRestartCount
                WorkingSetMB  = "N/A";               ServerUptime  = $uptimeStr
                RecentReboot  = ($recentTag -ne ""); CpuPct        = $cpuAvg
                MemPct        = $memPct;             MemUsedGB     = $usedMemGB
                MemTotalGB    = $totalMemGB;          MemFreeGB     = $freeMemGB
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
            DateTime      = $checkTime;          Zone          = $GroupName
            Server        = $ComputerName;        ServiceType   = "ContentServerAdmin"
            ServiceName   = $csAdmin.Name;        DisplayName   = $csAdmin.DisplayName
            Description   = $csAdmin.Description; Status        = $csAdmin.State
            Version       = "";                   JrePath       = ""
            HeapInitMB    = $null;                HeapMaxMB     = $null
            GcCollector   = "";                   GcWarnings    = "";             GcRecommend = ""
            RunAs         = $csAdmin.StartName;   ServiceUptime = $caUp
            RestartConfig = $caRestart;           AutoRestarts  = $caRestartCount
            WorkingSetMB  = "N/A";                ServerUptime  = $uptimeStr
            RecentReboot  = ($recentTag -ne "");  CpuPct        = $cpuAvg
            MemPct        = $memPct;              MemUsedGB     = $usedMemGB
            MemTotalGB    = $totalMemGB;           MemFreeGB     = $freeMemGB
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
        ComputerName     = $ComputerName;   GroupName        = $GroupName
        InstanceLabel    = $ComputerName;   Output           = $out
        CsvRows          = $csvRows;        OverallStatus    = $overallStatus
        TomcatVersion    = $tomcatVersion;  EventLines       = $eventLines
        DriveErrors      = $driveErrors;    DriveWarnings    = $driveWarnings
        InformantResults = $allInformant;   GcCollector      = $gcCollector
        GcWarnings       = $gcWarnings;     GcRecommend      = $gcRecommend
        MemPct           = $memPct;         CpuAvg           = $cpuAvg
        MemUsedGB        = $usedMemGB;      MemTotalGB       = $totalMemGB
        MemFreeGB        = $freeMemGB;      DrivesSummary    = $drivesSummaryForCsv
        Uptime           = $uptimeStr;      JobLog           = $jobLog
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
    Write-Host "Non-interactive session detected - skipping credential prompt." -ForegroundColor Gray
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
    if (-not $zoneSummary.Contains($grp)) {
        $zoneSummary[$grp] = @{ OK = 0; WARN = 0; DOWN = 0; CRITICAL = 0 }
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
Write-Log ""; Write-Log "======== Zone Rollup ========" -Color Cyan
foreach ($grp in $zoneSummary.Keys) {
    $s   = $zoneSummary[$grp]
    $tot = $s.OK + $s.WARN + $s.DOWN + $s.CRITICAL
    $col = if ($s.DOWN -gt 0 -or $s.CRITICAL -gt 0) {"Red"} elseif ($s.WARN -gt 0) {"Yellow"} else {"Green"}
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

# ── HTML ───────────────────────────────────────────────────────────────────────

# Stat counts (per service instance row)
$statTotal=0; $statOK=0; $statWarn=0; $statCrit=0; $statDown=0
foreach ($result in $results) {
    if ($result.CsvRows) {
        foreach ($row in $result.CsvRows) {
            $statTotal++
            switch ($row.OverallStatus) {"OK"{$statOK++}"WARN"{$statWarn++}"CRITICAL"{$statCrit++}"DOWN"{$statDown++}}
        }
    } elseif ($result.OverallStatus -eq "DOWN") { $statTotal++; $statDown++ }
}

# Zone / server / instance HTML
$zonesHtml    = ""
$sortedGroups = $results | Select-Object -ExpandProperty GroupName -Unique | Sort-Object

foreach ($grp in $sortedGroups) {
    $grpResults = @($results | Where-Object { $_.GroupName -eq $grp } | Sort-Object ComputerName)

    $zInstTotal=0; $zOK=0; $zWarn=0; $zCrit=0; $zDown=0
    foreach ($r in $grpResults) {
        if ($r.CsvRows) {
            foreach ($row in $r.CsvRows) {
                $zInstTotal++
                switch ($row.OverallStatus) {"OK"{$zOK++}"WARN"{$zWarn++}"CRITICAL"{$zCrit++}"DOWN"{$zDown++}}
            }
        } elseif ($r.OverallStatus -eq "DOWN") { $zInstTotal++; $zDown++ }
    }
    $zSev     = if ($zCrit -gt 0 -or $zDown -gt 0) {"crit"} elseif ($zWarn -gt 0) {"warn"} else {"ok"}
    $zBodyCls = if ($zSev -ne "ok") {"open"} else {""}
    $zId      = "z_" + ($grp -replace '[^a-zA-Z0-9]','_')

    $zCritStr = if ($zCrit -gt 0) {"<strong class='c-crit'>$zCrit crit</strong>"} else {"0 crit"}
    $zWarnStr = if ($zWarn -gt 0) {"<strong class='c-warn'>$zWarn warn</strong>"} else {"0 warn"}
    $zDownStr = if ($zDown -gt 0) {"<strong class='c-crit'>$zDown down</strong>"} else {"0 down"}
    $zCounts  = "$($grpResults.Count) server$(if($grpResults.Count -ne 1){'s'}) &nbsp;·&nbsp; " +
                "$zInstTotal instance$(if($zInstTotal -ne 1){'s'}) &nbsp;·&nbsp; $zCritStr &nbsp;·&nbsp; $zWarnStr &nbsp;·&nbsp; $zDownStr"

    $serversHtml = ""
    foreach ($result in $grpResults) {
        $sn    = $result.ComputerName
        $sSev  = switch ($result.OverallStatus) {"CRITICAL"{"crit"}"DOWN"{"down"}"WARN"{"warn"}default{""}}
        $sOpen = if ($sSev -in @("crit","down","warn")) {"open"} else {""}

        # Per-server flags
        $sf = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($de in $result.DriveErrors)   { $sf.Add([PSCustomObject]@{Sev="crit";Tag="DRIVE CRITICAL";Msg=$de}) }
        foreach ($dw in $result.DriveWarnings) { $sf.Add([PSCustomObject]@{Sev="warn";Tag="DRIVE WARN";    Msg=$dw}) }
        if ($result.MemPct -ge 90)             { $sf.Add([PSCustomObject]@{Sev="crit";Tag="MEM CRITICAL";  Msg="$($result.MemPct)% ($($result.MemUsedGB)/$($result.MemTotalGB) GB)"}) }
        elseif ($result.MemPct -ge 75)         { $sf.Add([PSCustomObject]@{Sev="warn";Tag="MEM WARN";      Msg="$($result.MemPct)% ($($result.MemUsedGB)/$($result.MemTotalGB) GB)"}) }
        if ($result.CpuAvg -ge 90)             { $sf.Add([PSCustomObject]@{Sev="crit";Tag="CPU CRITICAL";  Msg="$($result.CpuAvg)%"}) }
        elseif ($result.CpuAvg -ge 75)         { $sf.Add([PSCustomObject]@{Sev="warn";Tag="CPU WARN";      Msg="$($result.CpuAvg)%"}) }
        if ($result.Uptime -and $result.Uptime -ne "N/A") {
            $bm = [regex]::Match($result.Uptime,'booted: (.+)\)')
            if ($bm.Success) {
                try {
                    $bd = [datetime]::ParseExact($bm.Groups[1].Value.Trim(),"yyyy-MM-dd HH:mm:ss",$null)
                    if (((Get-Date)-$bd).TotalHours -lt 24) {
                        $sf.Add([PSCustomObject]@{Sev="warn";Tag="RECENT REBOOT";Msg="booted $($bm.Groups[1].Value.Trim())"})
                    }
                } catch {}
            }
        }
        foreach ($gw in $result.GcWarnings) { $sf.Add([PSCustomObject]@{Sev="warn";Tag="GC WARN";Msg=$gw}) }
        foreach ($instKey in $result.InformantResults.Keys) {
            foreach ($comp in $result.InformantResults[$instKey].Keys) {
                $ir = $result.InformantResults[$instKey][$comp]
                if ($ir.Status -eq "FAILURE") { $sf.Add([PSCustomObject]@{Sev="crit";Tag="INFORMANT FAILURE";Msg="$instKey · $comp"}) }
                elseif ($ir.Status -eq "ERROR")  { $sf.Add([PSCustomObject]@{Sev="crit";Tag="INFORMANT ERROR";  Msg="$instKey · $comp · $($ir.Detail)"}) }
                elseif ($ir.Slow)                { $sf.Add([PSCustomObject]@{Sev="warn";Tag="INFORMANT SLOW";   Msg="$instKey · $comp · $($ir.Ms)ms"}) }
            }
        }
        foreach ($el in $result.EventLines) { $sf.Add([PSCustomObject]@{Sev="warn";Tag="EVENT LOG";Msg=$el}) }

        $flagsHtml = ""
        if ($sf.Count -gt 0) {
            $fr = ($sf | Sort-Object {if($_.Sev -eq "crit"){0}else{1}} | ForEach-Object {
                "<div class='fp-row $($_.Sev)'><span class='fp-tag'>$(HtmlEncode $_.Tag)</span><span class='fp-msg'>$(HtmlEncode $_.Msg)</span></div>"
            }) -join ""
            $flagsHtml = "<div class='flags-panel'><div class='fp-title'>Flags</div><div class='fp-rows'>$fr</div></div>"
        }

        # Delta
        $deltaRows = ""
        if ($result.CsvRows) {
            foreach ($row in $result.CsvRows) {
                $key  = "$($row.Server)|$($row.ServiceName)"
                $prev = $prevData[$key]
                if ($prev) {
                    $cp = @()
                    if ($prev.Status  -ne $row.Status)  { $cp += "Status: $(HtmlEncode $prev.Status) &rarr; $(HtmlEncode $row.Status)" }
                    if ($prev.Version -and $row.Version -and $prev.Version -ne $row.Version) {
                        $cp += "Version: $(HtmlEncode $prev.Version) &rarr; $(HtmlEncode $row.Version)"
                    }
                    if ($cp) {
                        $deltaRows += "<div class='fp-row changed'><span class='fp-tag'>CHANGED</span><span class='fp-msg'>$(HtmlEncode $row.ServiceName): $($cp -join ' | ')</span></div>"
                    }
                }
            }
        }
        if ($deltaRows) {
            $flagsHtml += "<div class='flags-panel'><div class='fp-title'>Changes vs Previous Run</div><div class='fp-rows'>$deltaRows</div></div>"
        }

        # Service table rows
        $svcRowsHtml = ""
        if ($result.CsvRows) {
            $typeOrder  = @("Tomcat","ContentServer","ContentServerAdmin")
            $sortedRows = $result.CsvRows | Sort-Object { $i=$typeOrder.IndexOf($_.ServiceType); if($i -lt 0){99}else{$i} }
            foreach ($row in $sortedRows) {
                $rCls    = switch ($row.OverallStatus) {"CRITICAL"{"svc-crit"}"DOWN"{"svc-down"}"WARN"{"svc-warn"}default{""}}
                $stCls   = if ($row.Status -eq "Running") {"running"} else {"stopped"}
                $ovCls   = switch ($row.OverallStatus) {"OK"{"ok"}"WARN"{"warn"}"CRITICAL"{"crit"}"DOWN"{"down"}default{"na"}}
                $typeLbl = switch ($row.ServiceType) {"Tomcat"{"Tomcat"}"ContentServer"{"Content Server"}"ContentServerAdmin"{"CS Admin"}default{$row.ServiceType}}
                $heapStr = if ($row.HeapInitMB) {"$($row.HeapInitMB) / $($row.HeapMaxMB) MB"} else {"—"}
                $verStr  = if ($row.Version -and $row.Version -ne "") {HtmlEncode $row.Version} else {"—"}
                $wsStr   = if ($row.WorkingSetMB -and $row.WorkingSetMB -ne "N/A") {HtmlEncode $row.WorkingSetMB} else {"—"}
                $restStr = if ($null -ne $row.AutoRestarts) {HtmlEncode "$($row.AutoRestarts)"} else {"—"}
                $svcRowsHtml += "
                <tr class='$rCls'>
                  <td class='td-type'>$typeLbl</td>
                  <td class='td-mono'>$(HtmlEncode $row.ServiceName)</td>
                  <td><span class='chip $stCls'>$(HtmlEncode $row.Status.ToUpper())</span></td>
                  <td>$verStr</td>
                  <td class='td-mono'>$heapStr</td>
                  <td>$wsStr</td>
                  <td>$restStr</td>
                  <td><span class='chip $ovCls'>$(HtmlEncode $row.OverallStatus)</span></td>
                </tr>"
            }
        } else {
            $svcRowsHtml = "<tr><td colspan='8' class='td-err'>Host unreachable or CIM session failed</td></tr>"
        }

        $instCount = if ($result.CsvRows) {$result.CsvRows.Count} else {0}
        $uptShort  = ($result.Uptime -replace '\s*\(booted.*','').Trim()
        $srvMeta   = "$instCount svc$(if($instCount -ne 1){'s'}) &nbsp;·&nbsp; up $uptShort &nbsp;·&nbsp; CPU $($result.CpuAvg)% &nbsp;·&nbsp; Mem $($result.MemPct)%"

        $serversHtml += "
        <div class='srv-card'>
          <div class='srv-hdr $sSev' onclick='toggleSrv(this)'>
            <span class='arr'>&#9660;</span>
            <span class='srv-name'>$(HtmlEncode $sn)</span>
            <span class='srv-meta'>$srvMeta</span>
            <span class='chip $(if($sSev){"$sSev"}else{"ok"})' style='margin-left:auto'>$(HtmlEncode $result.OverallStatus)</span>
          </div>
          <div class='srv-body $sOpen'>
            <table class='svc-tbl'>
              <thead><tr>
                <th>Type</th><th>Service</th><th>Status</th><th>Version</th>
                <th>Heap Xms/Xmx</th><th>Working Set</th><th>Restarts 24h</th><th>Overall</th>
              </tr></thead>
              <tbody>$svcRowsHtml</tbody>
            </table>
            $flagsHtml
          </div>
        </div>"
    }

    $zonesHtml += "
    <div class='zone-wrap'>
      <div class='zone-hdr $zSev' onclick='toggleZone(this)'>
        <span class='arr'>&#9660;</span>
        <span class='zone-name'>$(HtmlEncode $grp)</span>
        <span class='zone-counts'>$zCounts</span>
        <button class='zone-tbtn' onclick='event.stopPropagation();toggleZoneServers(this)'>Expand Servers</button>
      </div>
      <div class='zone-body $zBodyCls' id='$zId'>$serversHtml</div>
    </div>"
}

$htmlContent = @"
<!DOCTYPE html>
<html lang='en'><head><meta charset='UTF-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Service Check - $timestamp</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f1117;--surf:#161b22;--surf2:#1c2128;--bdr:#21262d;
  --txt:#c9d1d9;--muted:#8b949e;--head:#e6edf3;
  --g:#3fb950;--gbg:#0d1f12;--gbdr:#238636;
  --y:#d29922;--ybg:#1f1a0d;--ybdr:#9e6a03;
  --r:#f85149;--rbg:#1f0d0d;--rbdr:#da3633;
  --b:#79c0ff;--bbg:#0d1320;--bbdr:#1f6feb;
  --al-ok:3px solid #238636;--al-w:3px solid #9e6a03;--al-c:3px solid #da3633;
}
body.mono{
  --bg:#f4f4f4;--surf:#fff;--surf2:#e6e6e6;--bdr:#bbb;
  --txt:#111;--muted:#555;--head:#000;
  --g:#155724;--gbg:#d4edda;--gbdr:#155724;
  --y:#856404;--ybg:#fff3cd;--ybdr:#856404;
  --r:#721c24;--rbg:#f8d7da;--rbdr:#721c24;
  --b:#004085;--bbg:#cce5ff;--bbdr:#004085;
  --al-ok:3px solid #155724;--al-w:3px solid #856404;--al-c:3px solid #721c24;
}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--txt);padding:20px;min-height:100vh;transition:background .2s,color .2s}
.topbar{display:flex;align-items:center;gap:12px;margin-bottom:18px;padding-bottom:14px;border-bottom:1px solid var(--bdr);flex-wrap:wrap}
.tb-title{font-size:17px;font-weight:700;color:var(--head)}
.tb-sub{font-size:11px;color:var(--muted);margin-top:1px}
.tb-right{margin-left:auto;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.tb-meta{font-size:11px;color:var(--muted);text-align:right;line-height:1.5}
.tbtn{cursor:pointer;font-size:11px;font-weight:600;padding:4px 11px;border-radius:6px;border:1px solid var(--bdr);background:var(--surf2);color:var(--txt);white-space:nowrap}
.tbtn:hover{border-color:var(--muted)}
.stat-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px}
.stat{padding:8px 18px;border-radius:8px;border:1px solid var(--bdr);background:var(--surf)}
.stat .n{font-size:24px;font-weight:700;line-height:1}
.stat .l{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.stat.ok .n{color:var(--g)}.stat.warn .n{color:var(--y)}.stat.crit .n,.stat.down .n{color:var(--r)}.stat.total .n{color:var(--b)}
.flags-strip{margin-bottom:18px}
.fs-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-bottom:7px}
.fs-list{display:flex;flex-wrap:wrap;gap:5px}
.fi{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:5px;font-size:11px;font-weight:600;border:1px solid}
.fi.crit{background:var(--rbg);color:var(--r);border-color:var(--rbdr)}
.fi.warn{background:var(--ybg);color:var(--y);border-color:var(--ybdr)}
.fi-tag{font-weight:700}.fi-msg{font-weight:400;opacity:.85}
.zone-wrap{margin-bottom:8px;border:1px solid var(--bdr);border-radius:9px;overflow:hidden}
.zone-hdr{display:flex;align-items:center;gap:9px;padding:9px 13px;cursor:pointer;background:var(--surf2);user-select:none;border-left:var(--al-ok);flex-wrap:wrap}
.zone-hdr.warn{border-left:var(--al-w)}.zone-hdr.crit,.zone-hdr.down{border-left:var(--al-c)}
.zone-name{font-weight:700;font-size:13px;color:var(--head)}
.zone-counts{font-size:11px;color:var(--muted)}
.zone-counts strong.c-crit{color:var(--r)}.zone-counts strong.c-warn{color:var(--y)}
.zone-tbtn{cursor:pointer;font-size:10px;font-weight:600;padding:2px 9px;border-radius:5px;border:1px solid var(--bdr);background:var(--bg);color:var(--muted);margin-left:auto;white-space:nowrap}
.zone-tbtn:hover{border-color:var(--muted);color:var(--txt)}
.zone-body{display:none;border-top:1px solid var(--bdr)}.zone-body.open{display:block}
.srv-card{border-bottom:1px solid var(--bdr);background:var(--surf)}.srv-card:last-child{border-bottom:none}
.srv-hdr{display:flex;align-items:center;gap:8px;padding:7px 13px 7px 26px;cursor:pointer;user-select:none;border-left:var(--al-ok);flex-wrap:wrap}
.srv-hdr.warn{border-left:var(--al-w)}.srv-hdr.crit,.srv-hdr.down{border-left:var(--al-c)}
.srv-name{font-size:13px;font-weight:600;color:var(--head)}
.srv-meta{font-size:11px;color:var(--muted)}
.srv-body{display:none;padding:10px 13px 13px 38px;border-top:1px solid var(--bdr);background:var(--bg)}.srv-body.open{display:block}
.arr{display:inline-block;width:14px;height:14px;border-radius:3px;background:var(--bdr);text-align:center;line-height:14px;font-size:8px;color:var(--muted);flex-shrink:0;transition:transform .15s}
.zone-hdr.closed .arr,.srv-hdr.closed .arr{transform:rotate(-90deg)}
.svc-tbl{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:10px}
.svc-tbl th{text-align:left;padding:4px 8px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:1px solid var(--bdr);white-space:nowrap}
.svc-tbl td{padding:5px 8px;border-bottom:1px solid var(--bdr);vertical-align:middle}
.svc-tbl tr:last-child td{border-bottom:none}
.svc-tbl tr.svc-crit td,.svc-tbl tr.svc-down td{background:var(--rbg)}
.svc-tbl tr.svc-warn td{background:var(--ybg)}
.td-type{font-weight:600;white-space:nowrap}.td-mono{font-family:'Cascadia Code','Consolas',monospace;font-size:11px}
.td-err{color:var(--r);padding:8px!important}
.chip{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;white-space:nowrap;border:1px solid}
.chip.ok,.chip.running{background:var(--gbg);color:var(--g);border-color:var(--gbdr)}
.chip.warn{background:var(--ybg);color:var(--y);border-color:var(--ybdr)}
.chip.crit,.chip.down,.chip.stopped,.chip.fail,.chip.err{background:var(--rbg);color:var(--r);border-color:var(--rbdr)}
.chip.other,.chip.info{background:var(--bbg);color:var(--b);border-color:var(--bbdr)}
.chip.na{background:var(--surf2);color:var(--muted);border-color:var(--bdr)}
.flags-panel{margin-top:6px}
.fp-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:5px}
.fp-rows{display:flex;flex-direction:column;gap:3px}
.fp-row{display:flex;align-items:flex-start;gap:8px;padding:4px 8px;border-radius:4px;font-size:11px;border-left:3px solid}
.fp-row.crit{background:var(--rbg);border-color:var(--rbdr);color:var(--r)}
.fp-row.warn{background:var(--ybg);border-color:var(--ybdr);color:var(--y)}
.fp-row.changed{background:var(--bbg);border-color:var(--bbdr);color:var(--b)}
.fp-tag{font-weight:700;white-space:nowrap;flex-shrink:0;min-width:140px}
.fp-msg{opacity:.9;word-break:break-word}
body.mono .chip{font-weight:900}
</style></head>
<body>
<div class='topbar'>
  <div>
    <div class='tb-title'>Service Check Report</div>
    <div class='tb-sub'>Tomcat &nbsp;·&nbsp; Content Server &nbsp;·&nbsp; CS Admin</div>
  </div>
  <div class='tb-right'>
    <div class='tb-meta'>
      <div><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
      <div><strong>Servers:</strong> $serverCount &nbsp;|&nbsp; <strong>Auto-restart:</strong> $(if ($AutoRestartStopped) {'On'} else {'Off'})</div>
    </div>
    <button class='tbtn' onclick='toggleMono(this)'>&#x2B1C; No-Color Mode</button>
    <button class='tbtn' onclick='toggleAllZones(true)'>&#x25BC; Expand All</button>
    <button class='tbtn' onclick='toggleAllZones(false)'>&#x25B6; Collapse All</button>
  </div>
</div>
<div class='stat-row'>
  <div class='stat total'><div class='n'>$statTotal</div><div class='l'>Instances</div></div>
  <div class='stat ok'>  <div class='n'>$statOK</div>   <div class='l'>Healthy</div></div>
  <div class='stat warn'><div class='n'>$statWarn</div> <div class='l'>Warning</div></div>
  <div class='stat crit'><div class='n'>$statCrit</div> <div class='l'>Critical</div></div>
  <div class='stat down'><div class='n'>$statDown</div> <div class='l'>Down</div></div>
</div>
$globalFlagsHtml
$zonesHtml
<script>
function toggleZone(hdr){
  var body=hdr.nextElementSibling,open=body.classList.toggle('open');
  hdr.classList.toggle('closed',!open);
}
function toggleSrv(hdr){
  var body=hdr.nextElementSibling,open=body.classList.toggle('open');
  hdr.classList.toggle('closed',!open);
}
function toggleAllZones(expand){
  document.querySelectorAll('.zone-body').forEach(function(b){b.classList.toggle('open',expand)});
  document.querySelectorAll('.zone-hdr').forEach(function(h){h.classList.toggle('closed',!expand)});
}
function toggleZoneServers(btn){
  var zone=btn.closest('.zone-wrap');
  var servers=zone.querySelectorAll('.srv-body');
  var anyOpen=[].some.call(servers,function(s){return s.classList.contains('open')});
  servers.forEach(function(s){s.classList.toggle('open',!anyOpen)});
  zone.querySelectorAll('.srv-hdr').forEach(function(h){h.classList.toggle('closed',anyOpen)});
  btn.textContent=anyOpen?'Expand Servers':'Collapse Servers';
}
function toggleMono(btn){
  var on=document.body.classList.toggle('mono');
  btn.textContent=on?'\uD83C\uDFA8 Color Mode':'\u2B1C No-Color Mode';
}
document.addEventListener('DOMContentLoaded',function(){
  document.querySelectorAll('.zone-hdr:not(.warn):not(.crit):not(.down)').forEach(function(h){h.classList.add('closed')});
  document.querySelectorAll('.srv-hdr:not(.warn):not(.crit):not(.down)').forEach(function(h){h.classList.add('closed')});
});
</script>
</body></html>
"@

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
        Write-Log "Failed to send alert email: $_" -Color Red
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

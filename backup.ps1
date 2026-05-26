#==================================================================================
#
#        SCRIPT: Remotely Compress with Multi-Service Control & Rotation (Parallel)
#
#        DESCRIPTION:
#        Stops a LIST of services, compresses a directory, and restarts the
#        original services. Performs backup rotation and logs all actions.
#        Dynamically resolves the instance name, Tomcat service name, and
#        Content Server directory from remote service metadata.
#
#        OPTIMISATIONS vs original:
#        - Phase 1 (discovery) runs in parallel across all servers
#        - Phase 3 (health check) runs in parallel across all servers
#        - Write-Log uses a StreamWriter (file kept open) instead of Add-Content
#          per line — eliminates repeated open/close overhead on every log entry
#        - Parallel job throttle replaced busy-wait (500ms poll) with Wait-Job -Any
#        - Compress-Archive replaced with ZipFile::CreateFromDirectory using
#          CompressionLevel.Fastest for significantly faster compression
#        - Fixed {INSTANCE} regex encoding artifacts
#
#        COMPATIBILITY: PowerShell 5.1
#
#        servers.txt format:
#        - Place in the same directory as this script.
#        - Zones defined using [Zone Name] headers.
#        - One FQDN per line. Instance name is resolved automatically.
#        - Lines starting with # are comments and ignored.
#        - Blank lines are ignored.
#
#        Example servers.txt:
#
#          [Production - Public]
#          prodpub1.domain.com
#          prodpub2.domain.com
#
#          [Production - Private]
#          prodpriv1.domain.com
#
#==================================================================================

#region Configuration
$configFile = Join-Path $PSScriptRoot "servers.txt"
if (-not (Test-Path $configFile)) {
    Write-Host "ERROR: Server config file not found: $configFile" -ForegroundColor Red
    Write-Host "Create a 'servers.txt' file in the same directory as this script." -ForegroundColor Yellow
    Write-Host "One FQDN per line. Zone headers: [Zone Name]" -ForegroundColor Yellow
    exit 1
}

$logDir          = Join-Path $PSScriptRoot "Logs"
$localLogPath    = Join-Path $logDir "CompressionLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$maxParallelJobs = 5
$maxBackups      = 2
$svcStopTimeout  = [TimeSpan]::FromSeconds(60)
$svcStartTimeout = [TimeSpan]::FromSeconds(60)

# Stop order: outermost dependents first. Restart is the reverse.
# OTSsystemCenterAgent and Tomcat depend on CS; CS Admin is auxiliary.
$staticServices = @('OTSsystemCenterAgent', '{TOMCAT}', '{INSTANCE}Admin', '{INSTANCE}')
#endregion

#region Helpers
# StreamWriter kept open for the script lifetime — avoids file open/close on every log line.
$script:_logWriter = $null

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO',
        [string]$Color = 'White',
        [switch]$Spacer
    )
    if ($Spacer) {
        $script:_logWriter.WriteLine('')
        Write-Host ''
        return
    }
    $entry = "[$Level] - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Write-Host $entry -ForegroundColor $Color
    $script:_logWriter.WriteLine($entry)
}

function Close-Log {
    if ($script:_logWriter) {
        $script:_logWriter.Flush()
        $script:_logWriter.Close()
        $script:_logWriter = $null
    }
}

function Parse-ServersFile {
    param([string]$Path)
    $groups  = [ordered]@{}
    $current = 'Ungrouped'
    $count   = 0
    foreach ($line in (Get-Content $Path)) {
        $t = $line.Trim()
        if ($t -match '^\s*$' -or $t -match '^\s*#') { continue }
        if ($t -match '^\[(.+)\]$') {
            $current = $Matches[1].Trim()
            if (-not $groups.Contains($current)) {
                $groups[$current] = New-Object 'System.Collections.Generic.List[string]'
            }
            continue
        }
        if (-not $groups.Contains($current)) {
            $groups[$current] = New-Object 'System.Collections.Generic.List[string]'
        }
        $groups[$current].Add($t)
        $count++
    }
    return $groups, $count
}

function Resolve-ServiceNames {
    param($Disc, [string]$Inst, [string]$Fqdn)
    $staticServices | ForEach-Object {
        if ($_ -eq '{TOMCAT}') {
            if ($Disc.TomcatServiceName) { $Disc.TomcatServiceName }
            else { Write-Log "  ${Fqdn}: Tomcat not resolved; excluded." -Level 'WARN' -Color Yellow }
        } else {
            $_ -replace '\{INSTANCE\}', $Inst
        }
    } | Where-Object { $_ }
}
#endregion

#region Discovery Script Block
$discoverScript = {
    $result = [pscustomobject]@{
        InstanceName      = $null
        TomcatServiceName = $null
        ContentServerDir  = $null
        Errors            = New-Object 'System.Collections.Generic.List[string]'
    }

    try {
        $allSvcs = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
    }
    catch {
        $result.Errors.Add("ERROR: Failed to query Win32_Service: $_")
        return $result
    }

    # --- Resolve Content Server service (exclude Admin variant) ---
    $csSvc = $allSvcs | Where-Object {
        $_.Description -like '*Content Server*' -and
        $_.Description -notlike '*Content Server Admin*'
    } | Select-Object -First 1

    if ($csSvc) {
        $result.InstanceName = $csSvc.Name

        if ($csSvc.PathName) {
            try {
                # Strip surrounding quotes and any arguments after the exe path
                # using .NET string methods to avoid -replace regex serialisation
                # issues on older PS remoting endpoints.
                $raw = $csSvc.PathName.Trim()
                if ($raw.StartsWith('"')) {
                    $closeQuote = $raw.IndexOf('"', 1)
                    if ($closeQuote -gt 1) {
                        $exePath = $raw.Substring(1, $closeQuote - 1)
                    } else {
                        $exePath = $raw.TrimStart('"')
                    }
                } else {
                    $spaceIdx = $raw.IndexOf(' ')
                    if ($spaceIdx -gt 0) {
                        $exePath = $raw.Substring(0, $spaceIdx)
                    } else {
                        $exePath = $raw
                    }
                }

                $dir   = [System.IO.Path]::GetDirectoryName($exePath)
                $csDir = $null
                for ($i = 0; $i -lt 6; $i++) {
                    if ([System.IO.Path]::GetFileName($dir) -ieq 'contentserver') {
                        $csDir = $dir; break
                    }
                    $candidate = [System.IO.Path]::Combine($dir, 'contentserver')
                    if (Test-Path $candidate -PathType Container) {
                        $csDir = $candidate; break
                    }
                    $parent = [System.IO.Path]::GetDirectoryName($dir)
                    if ([string]::IsNullOrEmpty($parent) -or $parent -eq $dir) { break }
                    $dir = $parent
                }

                if ($csDir) {
                    $result.ContentServerDir = $csDir
                } else {
                    $result.Errors.Add("WARNING: Could not locate 'contentserver' directory from exe path: $exePath")
                }
            }
            catch {
                $result.Errors.Add("WARNING: Error parsing PathName '$($csSvc.PathName)': $_")
            }
        } else {
            $result.Errors.Add("WARNING: Content Server service '$($csSvc.Name)' has no PathName.")
        }
    } else {
        $result.Errors.Add("WARNING: No Content Server service found (excluding Admin).")
    }

    # --- Resolve Tomcat service ---
    $tomcatSvc = $allSvcs | Where-Object { $_.DisplayName -like '*Apache*Tomcat*' } |
                 Select-Object -First 1
    if ($tomcatSvc) {
        $result.TomcatServiceName = $tomcatSvc.Name
    } else {
        $result.Errors.Add("WARNING: No service matching '*Apache*Tomcat*' found.")
    }

    return $result
}
#endregion

#region Remote Compression Script Block
$scriptBlock = {
    param(
        [string[]]$SvcNames,
        [string]$SrcPath,
        [string]$DestPath,
        [string]$DestFolder,
        [string]$SrcFolderName,
        [int]$MaxBackups,
        [int]$StopTimeoutSec,
        [int]$StartTimeoutSec
    )

    $host_ = $env:COMPUTERNAME

    function Wait-ServiceStatus {
        param([string]$Name, [string]$Status, [int]$TimeoutSec, [string]$Action)
        $svc     = Get-Service -Name $Name -ErrorAction Stop
        $timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        try {
            $svc.WaitForStatus($Status, $timeout)
            Write-Output "($host_) - Service '$Name' $Action."
        }
        catch [System.ServiceProcess.TimeoutException] {
            throw "Timed out waiting for '$Name' to reach '$Status' after ${TimeoutSec}s."
        }
    }

    $stopped = New-Object 'System.Collections.Generic.List[string]'

    try {
        foreach ($svcName in $SvcNames) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if (-not $svc) {
                Write-Output "($host_) - WARNING: Service '$svcName' not found. Skipping."
                continue
            }
            if ($svc.Status -eq 'Running') {
                Write-Output "($host_) - Stopping '$svcName'..."
                Stop-Service -Name $svcName -Force -ErrorAction Stop
                Wait-ServiceStatus -Name $svcName -Status 'Stopped' `
                    -TimeoutSec $StopTimeoutSec -Action 'stopped'
                $stopped.Add($svcName)
            } else {
                Write-Output "($host_) - '$svcName' already stopped."
            }
        }

        # ZipFile::CreateFromDirectory with Fastest compression is significantly
        # quicker than Compress-Archive (which defaults to Optimal).
        # Add-Type must be called inside the remote script block each time.
        if (-not (Test-Path $SrcPath -PathType Container)) {
            throw "Source path '$SrcPath' does not exist on $host_."
        }
        Write-Output "($host_) - Compressing '$SrcPath' -> '$DestPath'..."
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory(
            $SrcPath,
            $DestPath,
            [System.IO.Compression.CompressionLevel]::Fastest,
            $false
        )
        Write-Output "($host_) - Compression completed."

        $backups = Get-ChildItem -Path $DestFolder -Filter "${SrcFolderName}_*.zip" |
                   Sort-Object CreationTime
        $excess  = $backups.Count - $MaxBackups
        if ($excess -gt 0) {
            Write-Output "($host_) - Removing $excess old backup(s) (keeping $MaxBackups)."
            $backups | Select-Object -First $excess | ForEach-Object {
                Remove-Item $_.FullName -Force
                Write-Output "($host_) - Deleted: $($_.Name)"
            }
        } else {
            Write-Output "($host_) - $($backups.Count) backup(s) present. No rotation needed."
        }
    }
    catch { throw $_ }
    finally {
        if ($stopped.Count -gt 0) {
            [array]::Reverse($stopped)
            foreach ($svcName in $stopped) {
                try {
                    Write-Output "($host_) - Starting '$svcName'..."
                    Start-Service -Name $svcName -ErrorAction Stop
                    Wait-ServiceStatus -Name $svcName -Status 'Running' `
                        -TimeoutSec $StartTimeoutSec -Action 'started'
                }
                catch {
                    Write-Output "($host_) - ERROR restarting '$svcName': $_"
                }
            }
        }
    }
}
#endregion

#region Health Check Script Block
$verifyScript = {
    param([string[]]$SvcNames)
    $host_   = $env:COMPUTERNAME
    $results = New-Object 'System.Collections.Generic.List[pscustomobject]'

    foreach ($svcName in $SvcNames) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) {
            $results.Add([pscustomobject]@{ Name = $svcName; Status = 'NotFound'; Fixed = $false; Error = $null })
            continue
        }
        if ($svc.Status -eq 'Running') {
            $results.Add([pscustomobject]@{ Name = $svcName; Status = 'Running'; Fixed = $false; Error = $null })
            continue
        }

        $errMsg = $null
        $fixed  = $false
        try {
            Start-Service -Name $svcName -ErrorAction Stop
            $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
            $fixed = $true
        }
        catch { $errMsg = $_.Exception.Message }

        $results.Add([pscustomobject]@{
            Name   = $svcName
            Status = $svc.Status.ToString()
            Fixed  = $fixed
            Error  = $errMsg
        })
    }
    return $results
}
#endregion

#region Main
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

# Open StreamWriter once for the entire run (UTF-8, no BOM, no append).
$script:_logWriter = New-Object System.IO.StreamWriter(
    $localLogPath,
    $false,
    (New-Object System.Text.UTF8Encoding($false))
)
$script:_logWriter.AutoFlush = $false   # flush manually at end for best throughput

$startTime = Get-Date
Write-Log "---------------- SCRIPT EXECUTION STARTED ----------------" -Color Cyan
Write-Log "Started   : $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Gray
Write-Log "Log file  : $localLogPath" -Color Gray

$serverGroups, $totalEntries = Parse-ServersFile -Path $configFile

if ($totalEntries -eq 0) {
    Write-Log "ERROR: No valid server entries found in $configFile" -Level 'ERROR' -Color Red
    Close-Log
    exit 1
}

Write-Log "Servers   : $totalEntries across $($serverGroups.Keys.Count) zone(s)" -Color Gray
Write-Log -Spacer

# Flatten all FQDNs with group name for easier iteration
$allEntries = foreach ($group in $serverGroups.Keys) {
    foreach ($fqdn in $serverGroups[$group]) {
        [pscustomobject]@{ Fqdn = $fqdn; Group = $group }
    }
}

# --- Phase 1: Parallel Discovery ---
Write-Log "Phase 1: Discovering service names and paths (parallel)..." -Color Yellow

$discJobs = @{}
foreach ($e in $allEntries) {
    Write-Log "  Queuing discovery for $($e.Fqdn)..." -Color Gray
    try {
        $j = Invoke-Command -ComputerName $e.Fqdn -ScriptBlock $discoverScript -AsJob
        $j.Name = $e.Fqdn
        $discJobs[$e.Fqdn] = $j
    }
    catch {
        Write-Log "  $($e.Fqdn): Failed to queue discovery job - $_" -Level 'ERROR' -Color Red
        $discJobs[$e.Fqdn] = $null
    }
}

$activeDiscJobs = $discJobs.Values | Where-Object { $_ -ne $null }
if ($activeDiscJobs) { $activeDiscJobs | Wait-Job | Out-Null }

$discoveryResults = @{}
foreach ($e in $allEntries) {
    $j = $discJobs[$e.Fqdn]
    if ($null -eq $j) {
        $discoveryResults[$e.Fqdn] = [pscustomobject]@{
            InstanceName = $null; TomcatServiceName = $null; ContentServerDir = $null
            Errors = [string[]]@("Discovery job could not be created.")
        }
        continue
    }
    if ($j.State -eq 'Completed') {
        try {
            $disc = Receive-Job -Job $j -ErrorAction Stop
            $discoveryResults[$e.Fqdn] = $disc
            $disc.Errors | ForEach-Object { Write-Log "  $($e.Fqdn): $_" -Level 'WARN' -Color Yellow }
            Write-Log "  $($e.Fqdn): Instance='$($disc.InstanceName)'  Tomcat='$($disc.TomcatServiceName)'  CSDir='$($disc.ContentServerDir)'" -Color Gray
        }
        catch {
            Write-Log "  $($e.Fqdn): Discovery FAILED - $_" -Level 'ERROR' -Color Red
            $discoveryResults[$e.Fqdn] = [pscustomobject]@{
                InstanceName = $null; TomcatServiceName = $null; ContentServerDir = $null
                Errors = [string[]]@("Discovery failed: $_")
            }
        }
    } else {
        $err = $j.ChildJobs[0].Error | Select-Object -First 1
        $msg = if ($err) { $err.Exception.Message } else { "Job did not complete (State: $($j.State))." }
        Write-Log "  $($e.Fqdn): Discovery FAILED - $msg" -Level 'ERROR' -Color Red
        $discoveryResults[$e.Fqdn] = [pscustomobject]@{
            InstanceName = $null; TomcatServiceName = $null; ContentServerDir = $null
            Errors = [string[]]@("Discovery failed: $msg")
        }
    }
    Remove-Job -Job $j -Force
}

# --- Phase 2: Queue Compression Jobs ---
Write-Log -Spacer
Write-Log "Phase 2: Queuing compression jobs..." -Color Yellow

$jobs = New-Object 'System.Collections.Generic.List[pscustomobject]'

foreach ($e in $allEntries) {
    $disc = $discoveryResults[$e.Fqdn]

    if (-not $disc.InstanceName -or -not $disc.ContentServerDir) {
        Write-Log "SKIPPING $($e.Fqdn) -- incomplete discovery (Instance='$($disc.InstanceName)' CSDir='$($disc.ContentServerDir)')." -Level 'WARN' -Color Yellow
        continue
    }

    $inst     = $disc.InstanceName
    $svcNames = Resolve-ServiceNames -Disc $disc -Inst $inst -Fqdn $e.Fqdn

    $srcPath    = $disc.ContentServerDir
    $destFolder = Split-Path $srcPath -Parent
    $srcName    = Split-Path $srcPath -Leaf
    $destPath   = Join-Path $destFolder "${srcName}_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').zip"

    # Throttle: Wait-Job -Any reacts immediately when a slot opens (no 500ms busy-poll)
    if ((Get-Job -State Running).Count -ge $maxParallelJobs) {
        Wait-Job -Any | Out-Null
    }

    Write-Log "Queuing [$($e.Group)] $($e.Fqdn) | Instance: $inst | Tomcat: $($disc.TomcatServiceName) | Archive: $destPath" -Color Gray

    try {
        $job = Invoke-Command -ComputerName $e.Fqdn `
            -ScriptBlock $scriptBlock `
            -ArgumentList $svcNames, $srcPath, $destPath, $destFolder, $srcName, `
                          $maxBackups, $svcStopTimeout.TotalSeconds, $svcStartTimeout.TotalSeconds `
            -AsJob
        $job.Name = $e.Fqdn

        $jobs.Add([pscustomobject]@{
            Job          = $job
            ComputerName = $e.Fqdn
            GroupName    = $e.Group
            InstanceName = $inst
        })
    }
    catch {
        Write-Log "FAILED to queue job for $($e.Fqdn): $_" -Level 'ERROR' -Color Red
    }
}

if ($jobs.Count -eq 0) {
    Write-Log "No jobs were queued. Review discovery warnings above." -Level 'WARN' -Color Yellow
} else {
    Write-Log -Spacer
    Write-Log "All $($jobs.Count) job(s) queued. Waiting for completion..." -Color Yellow
    $jobs | ForEach-Object { $_.Job } | Wait-Job | Out-Null
    Write-Log "All jobs finished. Aggregating results." -Color Yellow

    $prevGroup = $null
    foreach ($entry in ($jobs | Sort-Object GroupName, ComputerName)) {
        if ($entry.GroupName -ne $prevGroup) {
            Write-Log -Spacer
            Write-Log "########################################" -Color Magenta
            Write-Log "# Zone: $($entry.GroupName)"            -Color Magenta
            Write-Log "########################################" -Color Magenta
            $prevGroup = $entry.GroupName
        }

        Write-Log "--- $($entry.ComputerName) ($($entry.InstanceName)) ---" -Color Cyan

        $entry.Job | Receive-Job | ForEach-Object {
            $color = switch -Regex ($_) {
                'ERROR|FAILED|does not exist' { 'Red'    }
                'WARNING'                     { 'Yellow' }
                'completed|started\.|stopped\.' { 'Green' }
                default                       { 'Gray'   }
            }
            Write-Log $_ -Color $color
        }

        if ($entry.Job.State -eq 'Completed') {
            Write-Log "RESULT: SUCCESS -- $($entry.ComputerName)" -Color Green
        } else {
            $err    = $entry.Job.ChildJobs[0].Error | Select-Object -First 1
            $errMsg = if ($err) { $err.Exception.Message } else { "Unreachable or access denied." }
            Write-Log "RESULT: FAILED -- $($entry.ComputerName) | $errMsg" -Level 'ERROR' -Color Red
        }
    }

    $jobs | ForEach-Object { $_.Job | Remove-Job -Force }
}

# --- Phase 3: Parallel Health Check ---
Write-Log -Spacer
Write-Log "Phase 3: Verifying service states on all processed servers (parallel)..." -Color Yellow

$verifyJobs = @{}
foreach ($entry in $jobs) {
    $disc     = $discoveryResults[$entry.ComputerName]
    $svcNames = Resolve-ServiceNames -Disc $disc -Inst $entry.InstanceName -Fqdn $entry.ComputerName
    try {
        $j = Invoke-Command -ComputerName $entry.ComputerName `
            -ScriptBlock $verifyScript `
            -ArgumentList (,$svcNames) `
            -AsJob
        $j.Name = $entry.ComputerName
        $verifyJobs[$entry.ComputerName] = $j
    }
    catch {
        Write-Log "  $($entry.ComputerName): Failed to queue health check job - $_" -Level 'ERROR' -Color Red
        $verifyJobs[$entry.ComputerName] = $null
    }
}

$activeVerifyJobs = $verifyJobs.Values | Where-Object { $_ -ne $null }
if ($activeVerifyJobs) { $activeVerifyJobs | Wait-Job | Out-Null }

$prevGroup = $null
foreach ($entry in ($jobs | Sort-Object GroupName, ComputerName)) {
    if ($entry.GroupName -ne $prevGroup) {
        Write-Log -Spacer
        Write-Log "########################################" -Color Magenta
        Write-Log "# Zone: $($entry.GroupName)"            -Color Magenta
        Write-Log "########################################" -Color Magenta
        $prevGroup = $entry.GroupName
    }

    Write-Log "--- $($entry.ComputerName) ($($entry.InstanceName)) ---" -Color Cyan

    $vj = $verifyJobs[$entry.ComputerName]
    if ($null -eq $vj) {
        Write-Log "  Health check job was not created for $($entry.ComputerName)." -Level 'ERROR' -Color Red
        continue
    }

    if ($vj.State -eq 'Completed') {
        try {
            $checks = Receive-Job -Job $vj -ErrorAction Stop
            foreach ($chk in $checks) {
                switch ($chk.Status) {
                    'Running'  { Write-Log "  [OK]        $($chk.Name) -- Running" -Color Green }
                    'NotFound' { Write-Log "  [SKIP]      $($chk.Name) -- Not found on host" -Level 'WARN' -Color Yellow }
                    default {
                        if ($chk.Fixed) {
                            Write-Log "  [RECOVERED] $($chk.Name) -- Was '$($chk.Status)', successfully started" -Color Green
                        } else {
                            Write-Log "  [FAILED]    $($chk.Name) -- Was '$($chk.Status)', could not start: $($chk.Error)" -Level 'ERROR' -Color Red
                        }
                    }
                }
            }
        }
        catch {
            Write-Log "  Health check error for $($entry.ComputerName): $_" -Level 'ERROR' -Color Red
        }
    } else {
        Write-Log "  Health check unreachable for $($entry.ComputerName) (State: $($vj.State))." -Level 'ERROR' -Color Red
    }
    Remove-Job -Job $vj -Force
}

$endTime = Get-Date
$dur     = $endTime - $startTime
Write-Log -Spacer
Write-Log "========================================" -Color Cyan
Write-Log "Completed : $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Cyan
Write-Log "Duration  : $($dur.ToString('mm\:ss'))"                  -Color Cyan
Write-Log "========================================" -Color Cyan
Write-Log "Log saved : $localLogPath" -Color Green
Write-Log "---------------- SCRIPT EXECUTION FINISHED ----------------"

Close-Log
#endregion

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

 

$logDir          = "C:\Logs"

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

function Write-Log {

    param(

        [string]$Message,

        [string]$Level = 'INFO',

        [string]$Color = 'White',

        [switch]$Spacer

    )

    if ($Spacer) {

        Add-Content -Path $localLogPath -Value ''

        Write-Host ''

        return

    }

    $entry = "[$Level] - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"

    Write-Host $entry -ForegroundColor $Color

    Add-Content -Path $localLogPath -Value $entry

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

                $groups[$current] = [System.Collections.Generic.List[string]]::new()

            }

            continue

        }

        if (-not $groups.Contains($current)) {

            $groups[$current] = [System.Collections.Generic.List[string]]::new()

        }

        $groups[$current].Add($t)

        $count++

    }

    return $groups, $count

}

#endregion

 

#region Discovery Script Block

$discoverScript = {

    $result = [pscustomobject]@{

        InstanceName      = $null

        TomcatServiceName = $null

        ContentServerDir  = $null

        Errors            = [System.Collections.Generic.List[string]]::new()

    }

 

    try {

        $allSvcs = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop

 

        # Resolve Content Server service (exclude Admin variant)

        $csSvc = $allSvcs | Where-Object {

            $_.Description -like '*Content Server*' -and

            $_.Description -notlike '*Content Server Admin*'

        } | Select-Object -First 1

 

        if ($csSvc) {

            $result.InstanceName = $csSvc.Name

 

            if ($csSvc.PathName) {

                # Strip quotes and args to get bare exe path

                $exePath = $csSvc.PathName -replace '^"([^"]+)".*$', '$1' `

                                           -replace '^([^\s]+\.exe).*$',  '$1'

 

                # Walk up directory tree looking for 'contentserver' folder

                $dir   = Split-Path $exePath -Parent

                $csDir = $null

                for ($i = 0; $i -lt 6; $i++) {

                    if ([IO.Path]::GetFileName($dir) -ieq 'contentserver') {

                        $csDir = $dir; break

                    }

                    $candidate = Join-Path $dir 'contentserver'

                    if (Test-Path $candidate -PathType Container) {

                        $csDir = $candidate; break

                    }

                    $parent = Split-Path $dir -Parent

                    if ($parent -eq $dir) { break }

                    $dir = $parent

                }

 

                if ($csDir) {

                    $result.ContentServerDir = $csDir

                } else {

                    $result.Errors.Add("WARNING: Could not locate 'contentserver' directory from exe path: $($csSvc.PathName)")

                }

            } else {

                $result.Errors.Add("WARNING: Content Server service '$($csSvc.Name)' has no PathName.")

            }

        } else {

            $result.Errors.Add("WARNING: No Content Server service found (excluding Admin).")

        }

 

        # Resolve Tomcat service

        $tomcatSvc = $allSvcs | Where-Object { $_.DisplayName -like '*Apache*Tomcat*' } |

                     Select-Object -First 1

        if ($tomcatSvc) {

            $result.TomcatServiceName = $tomcatSvc.Name

        } else {

            $result.Errors.Add("WARNING: No service matching '*Apache*Tomcat*' found.")

        }

    }

    catch {

        $result.Errors.Add("ERROR during discovery: $_")

    }

 

    return $result

}

#endregion

 

#region Remote Compression Script Block

$scriptBlock = {

    param(

        [string[]]$SvcNames,       # Ordered: stop first → last; restart reversed

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

 

    $stopped = [System.Collections.Generic.List[string]]::new()

 

    try {

        # --- Stop services (in provided order) ---

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

 

        # --- Compress ---

        if (-not (Test-Path $SrcPath -PathType Container)) {

            throw "Source path '$SrcPath' does not exist on $host_."

        }

        Write-Output "($host_) - Compressing '$SrcPath' → '$DestPath'..."

        Compress-Archive -Path $SrcPath -DestinationPath $DestPath -Force

        Write-Output "($host_) - Compression completed."

 

        # --- Backup rotation ---

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

        # --- Restart in reverse stop order ---

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

 

#region Main

if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

 

$startTime = Get-Date

Write-Log "---------------- SCRIPT EXECUTION STARTED ----------------" -Color Cyan

Write-Log "Started   : $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Gray

Write-Log "Log file  : $localLogPath" -Color Gray

 

$serverGroups, $totalEntries = Parse-ServersFile -Path $configFile

 

if ($totalEntries -eq 0) {

    Write-Log "ERROR: No valid server entries found in $configFile" -Level 'ERROR' -Color Red

    exit 1

}

 

Write-Log "Servers   : $totalEntries across $($serverGroups.Keys.Count) zone(s)" -Color Gray

Write-Log -Spacer

 

# --- Phase 1: Discovery ---

Write-Log "Phase 1: Discovering service names and paths..." -Color Yellow

$discoveryResults = @{}

 

foreach ($group in $serverGroups.Keys) {

    foreach ($fqdn in $serverGroups[$group]) {

        Write-Log "  Discovering $fqdn..." -Color Gray

        try {

            $disc = Invoke-Command -ComputerName $fqdn -ScriptBlock $discoverScript -ErrorAction Stop

            $discoveryResults[$fqdn] = $disc

            $disc.Errors | ForEach-Object { Write-Log "  ${fqdn}: $_" -Level 'WARN' -Color Yellow }

            Write-Log "  ${fqdn}: Instance='$($disc.InstanceName)'  Tomcat='$($disc.TomcatServiceName)'  CSDir='$($disc.ContentServerDir)'" -Color Gray

        }

        catch {

            Write-Log "  ${fqdn}: Discovery FAILED - $_" -Level 'ERROR' -Color Red

            $discoveryResults[$fqdn] = [pscustomobject]@{

                InstanceName      = $null

                TomcatServiceName = $null

                ContentServerDir  = $null

                Errors            = [System.Collections.Generic.List[string]]@("Discovery failed: $_")

            }

        }

    }

}

 

# --- Phase 2: Queue jobs ---

Write-Log -Spacer

Write-Log "Phase 2: Queuing compression jobs..." -Color Yellow

 

$jobs = [System.Collections.Generic.List[pscustomobject]]::new()

 

foreach ($group in $serverGroups.Keys) {

    foreach ($fqdn in $serverGroups[$group]) {

        $disc = $discoveryResults[$fqdn]

 

        # Require both InstanceName and ContentServerDir to proceed

        if (-not $disc.InstanceName -or -not $disc.ContentServerDir) {

            Write-Log "SKIPPING $fqdn — incomplete discovery (Instance='$($disc.InstanceName)' CSDir='$($disc.ContentServerDir)')." -Level 'WARN' -Color Yellow

            continue

        }

 

        $inst = $disc.InstanceName

 

        # Build ordered service list from template, substituting resolved names

        $svcNames = $staticServices | ForEach-Object {

            if ($_ -eq '{TOMCAT}') {

                if ($disc.TomcatServiceName) { $disc.TomcatServiceName }

                else { Write-Log "  ${fqdn}: Tomcat not resolved; excluded." -Level 'WARN' -Color Yellow }

            } else {

                $_ -replace '¥{INSTANCE¥}', $inst

            }

        } | Where-Object { $_ }   # drop nulls (missing Tomcat)

 

        $srcPath    = $disc.ContentServerDir

        $destFolder = Split-Path $srcPath -Parent

        $srcName    = Split-Path $srcPath -Leaf

        # Include HHmmss to avoid same-day collision

        $destPath   = Join-Path $destFolder "${srcName}_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').zip"

 

        while ((Get-Job -State Running).Count -ge $maxParallelJobs) { Start-Sleep -Milliseconds 500 }

 

        Write-Log "Queuing [$group] $fqdn | Instance: $inst | Tomcat: $($disc.TomcatServiceName) | Archive: $destPath" -Color Gray

 

        $job = Invoke-Command -ComputerName $fqdn `

            -ScriptBlock $scriptBlock `

            -ArgumentList $svcNames, $srcPath, $destPath, $destFolder, $srcName, `

                          $maxBackups, $svcStopTimeout.TotalSeconds, $svcStartTimeout.TotalSeconds `

            -AsJob

        $job.Name = $fqdn

 

        $jobs.Add([pscustomobject]@{

            Job          = $job

            ComputerName = $fqdn

            GroupName    = $group

            InstanceName = $inst

        })

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

                'completed|started¥.|stopped¥.' { 'Green'  }

                default                       { 'Gray'   }

            }

            Write-Log $_ -Color $color

        }

 

        if ($entry.Job.State -eq 'Completed') {

            Write-Log "RESULT: SUCCESS — $($entry.ComputerName)" -Color Green

        } else {

            $err    = $entry.Job.ChildJobs[0].Error | Select-Object -First 1

            $errMsg = if ($err) { $err.Exception.Message } else { "Unreachable or access denied." }

            Write-Log "RESULT: FAILED — $($entry.ComputerName) | $errMsg" -Level 'ERROR' -Color Red

        }

    }

 

    $jobs | ForEach-Object { $_.Job | Remove-Job -Force }

}

 

# --- Phase 3: Post-completion service health check ---

Write-Log -Spacer

Write-Log "Phase 3: Verifying service states on all processed servers..." -Color Yellow

 

$verifyScript = {

    param([string[]]$SvcNames)

    $host_ = $env:COMPUTERNAME

    $results = [System.Collections.Generic.List[pscustomobject]]::new()

 

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

 

        # Not running — attempt recovery

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

 

    $disc = $discoveryResults[$entry.ComputerName]

    $inst = $entry.InstanceName

 

    $svcNames = $staticServices | ForEach-Object {

        if ($_ -eq '{TOMCAT}') { $disc.TomcatServiceName }

        else { $_ -replace '¥{INSTANCE¥}', $inst }

    } | Where-Object { $_ }

 

    try {

        $checks = Invoke-Command -ComputerName $entry.ComputerName `

            -ScriptBlock $verifyScript `

            -ArgumentList (,$svcNames) `

            -ErrorAction Stop

 

        foreach ($chk in $checks) {

            switch ($chk.Status) {

                'Running'  {

                    Write-Log "  [OK]       $($chk.Name) — Running" -Color Green

                }

                'NotFound' {

                    Write-Log "  [SKIP]     $($chk.Name) — Not found on host" -Level 'WARN' -Color Yellow

                }

                default {

                    if ($chk.Fixed) {

                        Write-Log "  [RECOVERED] $($chk.Name) — Was '$($chk.Status)', successfully started" -Color Green

                    } else {

                        Write-Log "  [FAILED]    $($chk.Name) — Was '$($chk.Status)', could not start: $($chk.Error)" -Level 'ERROR' -Color Red

                    }

                }

            }

        }

    }

    catch {

        Write-Log "  Health check unreachable for $($entry.ComputerName): $_" -Level 'ERROR' -Color Red

    }

}

 

$endTime = Get-Date

$dur     = $endTime - $startTime

Write-Log -Spacer

Write-Log "========================================" -Color Cyan

Write-Log "Completed : $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Cyan

Write-Log "Duration  : $($dur.ToString('mm¥:ss'))"                  -Color Cyan

Write-Log "========================================" -Color Cyan

Write-Log "Log saved : $localLogPath" -Color Green

Write-Log "---------------- SCRIPT EXECUTION FINISHED ----------------"

#endregion#==================================================================================

#

#        SCRIPT: Remotely Compress with Multi-Service Control & Rotation (Parallel)

#

#        DESCRIPTION:

#        Stops a LIST of services, compresses a directory, and restarts the

#        original services. Performs backup rotation and logs all actions.

#        Dynamically resolves the instance name, Tomcat service name, and

#        Content Server directory from remote service metadata.

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

 

$logDir          = "C:¥Logs"

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

function Write-Log {

    param(

        [string]$Message,

        [string]$Level = 'INFO',

        [string]$Color = 'White',

        [switch]$Spacer

    )

    if ($Spacer) {

        Add-Content -Path $localLogPath -Value ''

        Write-Host ''

        return

    }

    $entry = "[$Level] - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"

    Write-Host $entry -ForegroundColor $Color

    Add-Content -Path $localLogPath -Value $entry

}

 

function Parse-ServersFile {

    param([string]$Path)

    $groups  = [ordered]@{}

    $current = 'Ungrouped'

    $count   = 0

    foreach ($line in (Get-Content $Path)) {

        $t = $line.Trim()

        if ($t -match '^¥s*$' -or $t -match '^¥s*#') { continue }

        if ($t -match '^¥[(.+)¥]$') {

            $current = $Matches[1].Trim()

            if (-not $groups.Contains($current)) {

                $groups[$current] = [System.Collections.Generic.List[string]]::new()

            }

            continue

        }

        if (-not $groups.Contains($current)) {

            $groups[$current] = [System.Collections.Generic.List[string]]::new()

        }

        $groups[$current].Add($t)

        $count++

    }

    return $groups, $count

}

#endregion

 

#region Discovery Script Block

$discoverScript = {

    $result = [pscustomobject]@{

        InstanceName      = $null

        TomcatServiceName = $null

        ContentServerDir  = $null

        Errors            = [System.Collections.Generic.List[string]]::new()

    }

 

    try {

        $allSvcs = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop

 

        # Resolve Content Server service (exclude Admin variant)

        $csSvc = $allSvcs | Where-Object {

            $_.Description -like '*Content Server*' -and

            $_.Description -notlike '*Content Server Admin*'

        } | Select-Object -First 1

 

        if ($csSvc) {

            $result.InstanceName = $csSvc.Name

 

            if ($csSvc.PathName) {

                # Strip quotes and args to get bare exe path

                $exePath = $csSvc.PathName -replace '^"([^"]+)".*$', '$1' `

                                           -replace '^([^¥s]+¥.exe).*$',  '$1'

 

                # Walk up directory tree looking for 'contentserver' folder

                $dir   = Split-Path $exePath -Parent

                $csDir = $null

                for ($i = 0; $i -lt 6; $i++) {

                    if ([IO.Path]::GetFileName($dir) -ieq 'contentserver') {

                        $csDir = $dir; break

                    }

                    $candidate = Join-Path $dir 'contentserver'

                    if (Test-Path $candidate -PathType Container) {

                        $csDir = $candidate; break

                    }

                    $parent = Split-Path $dir -Parent

                    if ($parent -eq $dir) { break }

                    $dir = $parent

                }

 

                if ($csDir) {

                    $result.ContentServerDir = $csDir

                } else {

                    $result.Errors.Add("WARNING: Could not locate 'contentserver' directory from exe path: $($csSvc.PathName)")

                }

            } else {

                $result.Errors.Add("WARNING: Content Server service '$($csSvc.Name)' has no PathName.")

            }

        } else {

            $result.Errors.Add("WARNING: No Content Server service found (excluding Admin).")

        }

 

        # Resolve Tomcat service

        $tomcatSvc = $allSvcs | Where-Object { $_.DisplayName -like '*Apache*Tomcat*' } |

                     Select-Object -First 1

        if ($tomcatSvc) {

            $result.TomcatServiceName = $tomcatSvc.Name

        } else {

            $result.Errors.Add("WARNING: No service matching '*Apache*Tomcat*' found.")

        }

    }

    catch {

        $result.Errors.Add("ERROR during discovery: $_")

    }

 

    return $result

}

#endregion

 

#region Remote Compression Script Block

$scriptBlock = {

    param(

        [string[]]$SvcNames,       # Ordered: stop first → last; restart reversed

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

 

    $stopped = [System.Collections.Generic.List[string]]::new()

 

    try {

        # --- Stop services (in provided order) ---

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

 

        # --- Compress ---

        if (-not (Test-Path $SrcPath -PathType Container)) {

            throw "Source path '$SrcPath' does not exist on $host_."

        }

        Write-Output "($host_) - Compressing '$SrcPath' → '$DestPath'..."

        Compress-Archive -Path $SrcPath -DestinationPath $DestPath -Force

        Write-Output "($host_) - Compression completed."

 

        # --- Backup rotation ---

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

        # --- Restart in reverse stop order ---

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

 

#region Main

if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

 

$startTime = Get-Date

Write-Log "---------------- SCRIPT EXECUTION STARTED ----------------" -Color Cyan

Write-Log "Started   : $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Gray

Write-Log "Log file  : $localLogPath" -Color Gray

 

$serverGroups, $totalEntries = Parse-ServersFile -Path $configFile

 

if ($totalEntries -eq 0) {

    Write-Log "ERROR: No valid server entries found in $configFile" -Level 'ERROR' -Color Red

    exit 1

}

 

Write-Log "Servers   : $totalEntries across $($serverGroups.Keys.Count) zone(s)" -Color Gray

Write-Log -Spacer

 

# --- Phase 1: Discovery ---

Write-Log "Phase 1: Discovering service names and paths..." -Color Yellow

$discoveryResults = @{}

 

foreach ($group in $serverGroups.Keys) {

    foreach ($fqdn in $serverGroups[$group]) {

        Write-Log "  Discovering $fqdn..." -Color Gray

        try {

            $disc = Invoke-Command -ComputerName $fqdn -ScriptBlock $discoverScript -ErrorAction Stop

            $discoveryResults[$fqdn] = $disc

            $disc.Errors | ForEach-Object { Write-Log "  ${fqdn}: $_" -Level 'WARN' -Color Yellow }

            Write-Log "  ${fqdn}: Instance='$($disc.InstanceName)'  Tomcat='$($disc.TomcatServiceName)'  CSDir='$($disc.ContentServerDir)'" -Color Gray

        }

        catch {

            Write-Log "  ${fqdn}: Discovery FAILED - $_" -Level 'ERROR' -Color Red

            $discoveryResults[$fqdn] = [pscustomobject]@{

                InstanceName      = $null

                TomcatServiceName = $null

                ContentServerDir  = $null

                Errors            = [System.Collections.Generic.List[string]]@("Discovery failed: $_")

            }

        }

    }

}

 

# --- Phase 2: Queue jobs ---

Write-Log -Spacer

Write-Log "Phase 2: Queuing compression jobs..." -Color Yellow

 

$jobs = [System.Collections.Generic.List[pscustomobject]]::new()

 

foreach ($group in $serverGroups.Keys) {

    foreach ($fqdn in $serverGroups[$group]) {

        $disc = $discoveryResults[$fqdn]

 

        # Require both InstanceName and ContentServerDir to proceed

        if (-not $disc.InstanceName -or -not $disc.ContentServerDir) {

            Write-Log "SKIPPING $fqdn — incomplete discovery (Instance='$($disc.InstanceName)' CSDir='$($disc.ContentServerDir)')." -Level 'WARN' -Color Yellow

            continue

        }

 

        $inst = $disc.InstanceName

 

        # Build ordered service list from template, substituting resolved names

        $svcNames = $staticServices | ForEach-Object {

            if ($_ -eq '{TOMCAT}') {

                if ($disc.TomcatServiceName) { $disc.TomcatServiceName }

                else { Write-Log "  ${fqdn}: Tomcat not resolved; excluded." -Level 'WARN' -Color Yellow }

            } else {

                $_ -replace '¥{INSTANCE¥}', $inst

            }

        } | Where-Object { $_ }   # drop nulls (missing Tomcat)

 

        $srcPath    = $disc.ContentServerDir

        $destFolder = Split-Path $srcPath -Parent

        $srcName    = Split-Path $srcPath -Leaf

        # Include HHmmss to avoid same-day collision

        $destPath   = Join-Path $destFolder "${srcName}_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').zip"

 

        while ((Get-Job -State Running).Count -ge $maxParallelJobs) { Start-Sleep -Milliseconds 500 }

 

        Write-Log "Queuing [$group] $fqdn | Instance: $inst | Tomcat: $($disc.TomcatServiceName) | Archive: $destPath" -Color Gray

 

        $job = Invoke-Command -ComputerName $fqdn `

            -ScriptBlock $scriptBlock `

            -ArgumentList $svcNames, $srcPath, $destPath, $destFolder, $srcName, `

                          $maxBackups, $svcStopTimeout.TotalSeconds, $svcStartTimeout.TotalSeconds `

            -AsJob

        $job.Name = $fqdn

 

        $jobs.Add([pscustomobject]@{

            Job          = $job

            ComputerName = $fqdn

            GroupName    = $group

            InstanceName = $inst

        })

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

                'completed|started¥.|stopped¥.' { 'Green'  }

                default                       { 'Gray'   }

            }

            Write-Log $_ -Color $color

        }

 

        if ($entry.Job.State -eq 'Completed') {

            Write-Log "RESULT: SUCCESS — $($entry.ComputerName)" -Color Green

        } else {

            $err    = $entry.Job.ChildJobs[0].Error | Select-Object -First 1

            $errMsg = if ($err) { $err.Exception.Message } else { "Unreachable or access denied." }

            Write-Log "RESULT: FAILED — $($entry.ComputerName) | $errMsg" -Level 'ERROR' -Color Red

        }

    }

 

    $jobs | ForEach-Object { $_.Job | Remove-Job -Force }

}

 

# --- Phase 3: Post-completion service health check ---

Write-Log -Spacer

Write-Log "Phase 3: Verifying service states on all processed servers..." -Color Yellow

 

$verifyScript = {

    param([string[]]$SvcNames)

    $host_ = $env:COMPUTERNAME

    $results = [System.Collections.Generic.List[pscustomobject]]::new()

 

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

 

        # Not running — attempt recovery

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

 

    $disc = $discoveryResults[$entry.ComputerName]

    $inst = $entry.InstanceName

 

    $svcNames = $staticServices | ForEach-Object {

        if ($_ -eq '{TOMCAT}') { $disc.TomcatServiceName }

        else { $_ -replace '¥{INSTANCE¥}', $inst }

    } | Where-Object { $_ }

 

    try {

        $checks = Invoke-Command -ComputerName $entry.ComputerName `

            -ScriptBlock $verifyScript `

            -ArgumentList (,$svcNames) `

            -ErrorAction Stop

 

        foreach ($chk in $checks) {

            switch ($chk.Status) {

                'Running'  {

                    Write-Log "  [OK]       $($chk.Name) — Running" -Color Green

                }

                'NotFound' {

                    Write-Log "  [SKIP]     $($chk.Name) — Not found on host" -Level 'WARN' -Color Yellow

                }

                default {

                    if ($chk.Fixed) {

                        Write-Log "  [RECOVERED] $($chk.Name) — Was '$($chk.Status)', successfully started" -Color Green

                    } else {

                        Write-Log "  [FAILED]    $($chk.Name) — Was '$($chk.Status)', could not start: $($chk.Error)" -Level 'ERROR' -Color Red

                    }

                }

            }

        }

    }

    catch {

        Write-Log "  Health check unreachable for $($entry.ComputerName): $_" -Level 'ERROR' -Color Red

    }

}

 

$endTime = Get-Date

$dur     = $endTime - $startTime

Write-Log -Spacer

Write-Log "========================================" -Color Cyan

Write-Log "Completed : $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Cyan

Write-Log "Duration  : $($dur.ToString('mm¥:ss'))"                  -Color Cyan

Write-Log "========================================" -Color Cyan

Write-Log "Log saved : $localLogPath" -Color Green

Write-Log "---------------- SCRIPT EXECUTION FINISHED ----------------"

#endregion

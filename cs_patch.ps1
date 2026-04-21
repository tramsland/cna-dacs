#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Content Server Patch Deployment Script
.DESCRIPTION
    Deploys zip patch files from a local patches directory to remote Content Server
    installations listed in servers.txt. Analyses each zip before deployment,
    backs up any files that will be overwritten, extracts the patch preserving
    directory structure, and optionally restarts Content Server services.
.PARAMETER SkipCredentialPrompt
    Skip the alternate-credentials prompt for non-interactive / remote execution.
.PARAMETER WhatIf
    Show what would be executed without making any changes.
.NOTES
    - Patch files must be .zip format in a 'patches' subfolder alongside this script
    - Content Server path: E:\customers\dacs\contentserver
    - servers.txt format:
        [ZoneName]
        server1.fqdn.com
        server2.fqdn.com
#>
param(
    [switch]$SkipCredentialPrompt,
    [switch]$WhatIf
)

# ============================================================
# CONFIGURATION
# ============================================================
$scriptDir      = Split-Path -Parent $MyInvocation.MyCommand.Definition
$configFile     = Join-Path $scriptDir "servers.txt"
$patchDir       = Join-Path $scriptDir "patches"
$outputDir      = Join-Path $scriptDir "patch-reports"
$csRemotePath   = "E:\customers\dacs\contentserver"
$maxParallelJobs = 5
$jobTimeoutSec  = 600  # 10 min per server — allow time for large patches

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile   = Join-Path $outputDir "PatchDeploy_$timestamp.log"
$htmlFile  = Join-Path $outputDir "PatchDeploy_$timestamp.html"

# ============================================================
# LOGGING
# ============================================================
function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Add-Content -Path $logFile -Value $entry
    Write-Host $entry -ForegroundColor $Color
}

# ============================================================
# LOAD SERVERS.TXT
# ============================================================
if (-not (Test-Path $configFile)) {
    Write-Host "ERROR: servers.txt not found at $configFile" -ForegroundColor Red
    exit 1
}

$serverGroups = [ordered]@{}
$currentGroup = "Ungrouped"
foreach ($line in (Get-Content $configFile)) {
    $t = $line.Trim()
    if ($t -match '^\s*$' -or $t -match '^\s*#') { continue }
    if ($t -match '^\[(.+)\]$') {
        $currentGroup = $Matches[1].Trim()
        if (-not $serverGroups.Contains($currentGroup)) {
            $serverGroups[$currentGroup] = [System.Collections.Generic.List[string]]::new()
        }
        continue
    }
    if (-not $serverGroups.Contains($currentGroup)) {
        $serverGroups[$currentGroup] = [System.Collections.Generic.List[string]]::new()
    }
    $serverGroups[$currentGroup].Add($t)
}

$allServers = [System.Collections.Generic.List[hashtable]]::new()
foreach ($grp in $serverGroups.Keys) {
    foreach ($srv in $serverGroups[$grp]) {
        $allServers.Add(@{ Server = $srv; Group = $grp })
    }
}

if ($allServers.Count -eq 0) {
    Write-Host "ERROR: No servers found in $configFile" -ForegroundColor Red
    exit 1
}

# ============================================================
# LOAD PATCH FILES
# ============================================================
if (-not (Test-Path $patchDir)) {
    Write-Host "ERROR: patches directory not found at $patchDir" -ForegroundColor Red
    exit 1
}

$patchFiles = @(Get-ChildItem -Path $patchDir -Filter "*.zip" | Sort-Object Name)
if ($patchFiles.Count -eq 0) {
    Write-Host "ERROR: No .zip patch files found in $patchDir" -ForegroundColor Red
    exit 1
}

# ============================================================
# CREDENTIAL PROMPT (console-safe)
# ============================================================
$Credential = $null
if (-not $SkipCredentialPrompt) {
    $hasConsole = $true
    try { [void][System.Console]::KeyAvailable } catch { $hasConsole = $false }

    if ($hasConsole) {
        Write-Host "Use alternate credentials? (y/n)  [auto-skipping in 10 seconds]" -ForegroundColor Cyan
        $useCreds = ""
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
        if ($useCreds -eq "y") {
            $Credential = Get-Credential -Message "Enter credentials for remote servers"
        }
    } else {
        Write-Host "Non-interactive mode detected - skipping credential prompt." -ForegroundColor Gray
    }
} else {
    Write-Host "Credential prompt skipped (-SkipCredentialPrompt)." -ForegroundColor Gray
}

# ============================================================
# BANNER
# ============================================================
Clear-Host
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Content Server Patch Deployment$(if($WhatIf){' [WHATIF]'})" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

Write-Log "Content Server Patch Deployment started" -Color Cyan
Write-Log "Patch directory : $patchDir" -Color Gray
Write-Log "Target path     : $csRemotePath" -Color Gray
Write-Log "Log             : $logFile" -Color Gray
Write-Log ""

# ============================================================
# DISPLAY PATCHES FOUND
# ============================================================
Write-Host "  Patch files found:" -ForegroundColor Cyan
foreach ($p in $patchFiles) {
    $sizeMB = [math]::Round($p.Length / 1MB, 2)
    Write-Host "    $($p.Name)  ($sizeMB MB)" -ForegroundColor White
}
Write-Host ""

# ============================================================
# DISPLAY SERVERS + ALLOW EXCLUSIONS
# ============================================================
Write-Host "  Servers loaded from servers.txt:" -ForegroundColor Cyan
for ($i = 0; $i -lt $allServers.Count; $i++) {
    Write-Host "  [$i] $($allServers[$i].Server)  ($($allServers[$i].Group))" -ForegroundColor White
}
Write-Host ""

$hasConsoleForExclude = $true
try { [void][System.Console]::KeyAvailable } catch { $hasConsoleForExclude = $false }

$excludedServers = [System.Collections.Generic.List[string]]::new()
$targetServers   = [System.Collections.Generic.List[hashtable]]::new()

if ($hasConsoleForExclude) {
    Write-Host "  Exclude any servers? Enter comma-separated numbers or press Enter to deploy to all." -ForegroundColor Yellow
    $excludeInput = (Read-Host "  Exclude (e.g. 0,2,3 or blank for all)").Trim()

    $excludeIndices = [System.Collections.Generic.List[int]]::new()
    if (-not [string]::IsNullOrWhiteSpace($excludeInput)) {
        foreach ($part in ($excludeInput -split ",\s*")) {
            if ($part -match "^\d+$") {
                $idx = [int]$part
                if ($idx -ge 0 -and $idx -lt $allServers.Count) {
                    $excludeIndices.Add($idx)
                    $excludedServers.Add($allServers[$idx].Server)
                }
            }
        }
    }

    for ($i = 0; $i -lt $allServers.Count; $i++) {
        if (-not $excludeIndices.Contains($i)) {
            $targetServers.Add($allServers[$i])
        }
    }
} else {
    # Non-interactive — deploy to all
    $targetServers.AddRange($allServers)
}

if ($targetServers.Count -eq 0) {
    Write-Log "No target servers remaining after exclusions." -Color Yellow
    exit 0
}

Write-Host ""
Write-Host "  Deploying to $($targetServers.Count) server(s):" -ForegroundColor Cyan
foreach ($s in $targetServers) {
    Write-Host "    $($s.Server)  ($($s.Group))" -ForegroundColor White
}
if ($excludedServers.Count -gt 0) {
    Write-Host "  Excluded: $($excludedServers -join ', ')" -ForegroundColor Yellow
}
Write-Host ""

# ============================================================
# CONFIRM BEFORE PROCEEDING
# ============================================================
if ($hasConsoleForExclude -and -not $WhatIf) {
    $confirm = (Read-Host "  Proceed with deployment? (y/n)").ToLower()
    if ($confirm -ne 'y') {
        Write-Log "Deployment cancelled by user." -Color Yellow
        exit 0
    }
} elseif ($WhatIf) {
    Write-Host "  [WHATIF] Dry run — no changes will be made." -ForegroundColor Magenta
}

Write-Log ""
Write-Log "Starting parallel deployment to $($targetServers.Count) server(s)..." -Color Yellow
Write-Log ""

# ============================================================
# ANALYSE ZIP FILES LOCALLY — build file manifest per patch
# ============================================================
Write-Log "Analysing patch files..." -Color Cyan

$patchManifests = [System.Collections.Generic.List[PSCustomObject]]::new()
Add-Type -AssemblyName System.IO.Compression.FileSystem

foreach ($patch in $patchFiles) {
    $entries = [System.Collections.Generic.List[string]]::new()
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($patch.FullName)
        foreach ($entry in $zip.Entries) {
            if (-not $entry.FullName.EndsWith("/")) {
                # Normalise to backslash for Windows path comparison
                $entries.Add($entry.FullName -replace "/", "\")
            }
        }
        $zip.Dispose()
        Write-Log "  $($patch.Name) — $($entries.Count) file(s)" -Color Gray
    } catch {
        Write-Log "  ERROR reading $($patch.Name): $_" -Color Red
        continue
    }
    $patchManifests.Add([PSCustomObject]@{
        Name     = $patch.Name
        FullPath = $patch.FullName
        SizeMB   = [math]::Round($patch.Length / 1MB, 2)
        Entries  = $entries
    })
}

if ($patchManifests.Count -eq 0) {
    Write-Log "No valid patch files could be read. Exiting." -Color Red
    exit 1
}

# Serialise patch data for passing into job (jobs can't take complex objects easily)
$patchData = $patchManifests | ForEach-Object {
    [PSCustomObject]@{
        Name     = $_.Name
        FullPath = $_.FullPath
        SizeMB   = $_.SizeMB
        Entries  = @($_.Entries)
    }
}

# ============================================================
# DEPLOY SCRIPT BLOCK (runs per server in parallel job)
# ============================================================
$deployScriptBlock = {
    param(
        [string]  $ComputerName,
        [string]  $GroupName,
        [object[]]$PatchData,
        [string]  $CsRemotePath,
        [System.Management.Automation.PSCredential]$Credential,
        [bool]    $WhatIf
    )

    $result = [PSCustomObject]@{
        ComputerName   = $ComputerName
        GroupName      = $GroupName
        OverallStatus  = "OK"
        PatchResults   = [System.Collections.Generic.List[PSCustomObject]]::new()
        CSInstances    = [System.Collections.Generic.List[string]]::new()
        Output         = [System.Collections.Generic.List[string]]::new()
        Error          = $null
    }

    # ── Ping ─────────────────────────────────────────────────────────────────
    $pingOk = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (-not $pingOk) {
        $result.Error         = "Host unreachable (no ping response)"
        $result.OverallStatus = "ERROR"
        $result.Output.Add("  ERROR: $($result.Error)")
        return $result
    }

    # ── Copy patches to remote temp dir via PSSession ─────────────────────────
    $sessionParams = @{ ComputerName = $ComputerName; ErrorAction = "Stop" }
    if ($Credential) { $sessionParams["Credential"] = $Credential }

    try {
        $session = New-PSSession @sessionParams
    } catch {
        $result.Error         = "PSSession failed: $_"
        $result.OverallStatus = "ERROR"
        $result.Output.Add("  ERROR: $($result.Error)")
        return $result
    }

    try {
        # Create remote temp staging directory
        $remoteTempDir = Invoke-Command -Session $session -ScriptBlock {
            $tmp = Join-Path $env:TEMP "cs_patch_$(Get-Date -Format 'yyyyMMddHHmmss')"
            New-Item -ItemType Directory -Path $tmp -Force | Out-Null
            return $tmp
        }

        $result.Output.Add("  Staging dir : $remoteTempDir")

        # Copy each patch zip to remote temp
        foreach ($patch in $PatchData) {
            $result.Output.Add("  Copying     : $($patch.Name) ($($patch.SizeMB) MB) → $ComputerName")
            if (-not $WhatIf) {
                try {
                    Copy-Item -Path $patch.FullPath `
                              -Destination "$remoteTempDir\$($patch.Name)" `
                              -ToSession $session `
                              -ErrorAction Stop
                } catch {
                    $result.Output.Add("  ERROR copying $($patch.Name): $_")
                    $result.OverallStatus = "ERROR"
                    continue
                }
            } else {
                $result.Output.Add("  [WHATIF] Would copy $($patch.Name) to $ComputerName:$remoteTempDir")
            }
        }

        # ── Run extraction + backup on remote server ──────────────────────────
        $remoteResult = Invoke-Command -Session $session -ScriptBlock {
            param(
                [object[]]$PatchData,
                [string]  $CsRemotePath,
                [string]  $TempDir,
                [bool]    $WhatIf,
                [string]  $Timestamp
            )

            Add-Type -AssemblyName System.IO.Compression.FileSystem

            $out         = [System.Collections.Generic.List[string]]::new()
            $patchResults = [System.Collections.Generic.List[PSCustomObject]]::new()
            $csInstances = [System.Collections.Generic.List[string]]::new()

            # ── Verify content server path exists ─────────────────────────────
            if (-not (Test-Path $CsRemotePath)) {
                return [PSCustomObject]@{
                    Success      = $false
                    Error        = "Content Server path not found: $CsRemotePath"
                    Output       = $out
                    PatchResults = $patchResults
                    CSInstances  = $csInstances
                }
            }

            # ── Find Content Server instances ─────────────────────────────────
            $csSvcs = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
                      Where-Object {
                          $_.Description -like "*Content Server*" -and
                          $_.Description -notlike "*Content Server Admin*"
                      }

            foreach ($svc in $csSvcs) {
                $csInstances.Add($svc.Name)
            }

            $out.Add("  CS path     : $CsRemotePath")
            $out.Add("  CS instances: $(if($csInstances.Count -gt 0){$csInstances -join ', '}else{'(none found)'})")

            # ── Process each patch ────────────────────────────────────────────
            # If multiple patches, use a single date-stamped backup file name
            $useMultiBackup   = $PatchData.Count -gt 1
            $multiBackupName  = "patch_backup_$Timestamp.backup"
            $multiBackupPath  = Join-Path $CsRemotePath $multiBackupName
            $multiBackupFiles = [System.Collections.Generic.List[string]]::new()

            foreach ($patch in $PatchData) {
                $zipPath     = Join-Path $TempDir $patch.Name
                $backupName  = if ($useMultiBackup) { $multiBackupName } else { "$($patch.Name).backup" }
                $backupPath  = Join-Path $CsRemotePath $backupName
                $patchResult = [PSCustomObject]@{
                    PatchName    = $patch.Name
                    FilesInZip   = $patch.Entries.Count
                    FilesUpdated = 0
                    FilesBacked  = 0
                    FilesNew     = 0
                    BackupFile   = $backupName
                    Status       = "OK"
                    FileDetail   = [System.Collections.Generic.List[string]]::new()
                    Error        = $null
                }

                $out.Add("")
                $out.Add("  ── Patch: $($patch.Name) ──────────────────────────")

                if (-not (Test-Path $zipPath) -and -not $WhatIf) {
                    $patchResult.Status = "ERROR"
                    $patchResult.Error  = "Zip not found in staging: $zipPath"
                    $out.Add("  ERROR: $($patchResult.Error)")
                    $patchResults.Add($patchResult)
                    continue
                }

                # ── Analyse which files will be overwritten ───────────────────
                $toBackup = [System.Collections.Generic.List[string]]::new()
                $toNew    = [System.Collections.Generic.List[string]]::new()

                foreach ($entry in $patch.Entries) {
                    $destFile = Join-Path $CsRemotePath $entry
                    if (Test-Path $destFile) {
                        $toBackup.Add($entry)
                    } else {
                        $toNew.Add($entry)
                    }
                }

                $out.Add("  Files in zip : $($patch.Entries.Count)")
                $out.Add("  Will overwrite: $($toBackup.Count)  |  New files: $($toNew.Count)")

                foreach ($f in $toBackup) { $out.Add("    [UPDATE] $f") }
                foreach ($f in $toNew)    { $out.Add("    [NEW]    $f") }

                $patchResult.FilesUpdated = $toBackup.Count
                $patchResult.FilesNew     = $toNew.Count

                # ── Backup files that will be overwritten ─────────────────────
                if ($toBackup.Count -gt 0) {
                    $out.Add("  Backing up $($toBackup.Count) file(s) → $backupName")

                    if (-not $WhatIf) {
                        try {
                            if ($useMultiBackup) {
                                # Accumulate into shared backup zip
                                $multiBackupFiles.AddRange($toBackup)
                            } else {
                                # Single patch — create dedicated backup zip
                                if (Test-Path $backupPath) { Remove-Item $backupPath -Force }
                                $backupZip = [System.IO.Compression.ZipFile]::Open(
                                    $backupPath,
                                    [System.IO.Compression.ZipArchiveMode]::Create)
                                foreach ($entry in $toBackup) {
                                    $srcFile = Join-Path $CsRemotePath $entry
                                    if (Test-Path $srcFile) {
                                        $entryInZip = $entry -replace "\\","/"
                                        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                                            $backupZip, $srcFile, $entryInZip,
                                            [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
                                        $patchResult.FilesBacked++
                                    }
                                }
                                $backupZip.Dispose()
                                $out.Add("  Backup saved : $backupPath")
                            }
                        } catch {
                            $patchResult.Status = "WARN"
                            $out.Add("  WARN: Backup failed: $_")
                        }
                    } else {
                        $out.Add("  [WHATIF] Would create backup: $backupPath")
                        $patchResult.FilesBacked = $toBackup.Count
                    }
                }

                # ── Extract patch ─────────────────────────────────────────────
                if (-not $WhatIf) {
                    try {
                        $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
                        foreach ($entry in $zip.Entries) {
                            if ($entry.FullName.EndsWith("/")) { continue }  # skip dirs
                            $destPath = Join-Path $CsRemotePath ($entry.FullName -replace "/","\")
                            $destDir  = Split-Path $destPath -Parent
                            if (-not (Test-Path $destDir)) {
                                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                            }
                            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destPath, $true)
                        }
                        $zip.Dispose()
                        $out.Add("  Extracted    : $($patch.Entries.Count) file(s) → $CsRemotePath")
                        $patchResult.Status = "OK"
                    } catch {
                        $patchResult.Status = "ERROR"
                        $patchResult.Error  = "Extraction failed: $_"
                        $out.Add("  ERROR: $($patchResult.Error)")
                    }
                } else {
                    $out.Add("  [WHATIF] Would extract $($patch.Entries.Count) file(s) to $CsRemotePath")
                }

                $patchResults.Add($patchResult)
            }

            # ── Write combined backup zip if multiple patches ──────────────────
            if ($useMultiBackup -and $multiBackupFiles.Count -gt 0 -and -not $WhatIf) {
                try {
                    if (Test-Path $multiBackupPath) { Remove-Item $multiBackupPath -Force }
                    $backupZip = [System.IO.Compression.ZipFile]::Open(
                        $multiBackupPath,
                        [System.IO.Compression.ZipArchiveMode]::Create)
                    $backedCount = 0
                    # Deduplicate — later patches win, so back up original only once
                    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    foreach ($entry in $multiBackupFiles) {
                        if ($seen.Add($entry)) {
                            $srcFile = Join-Path $CsRemotePath $entry
                            if (Test-Path $srcFile) {
                                $entryInZip = $entry -replace "\\","/"
                                [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                                    $backupZip, $srcFile, $entryInZip,
                                    [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
                                $backedCount++
                            }
                        }
                    }
                    $backupZip.Dispose()
                    $out.Add("")
                    $out.Add("  Combined backup: $multiBackupPath ($backedCount unique file(s))")
                    # Update FilesBacked on each patch result
                    foreach ($pr in $patchResults) { $pr.FilesBacked = $backedCount }
                } catch {
                    $out.Add("  WARN: Combined backup failed: $_")
                }
            }

            # ── Cleanup temp dir ──────────────────────────────────────────────
            if (-not $WhatIf -and (Test-Path $TempDir)) {
                Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
            }

            return [PSCustomObject]@{
                Success      = $true
                Error        = $null
                Output       = $out
                PatchResults = $patchResults
                CSInstances  = $csInstances
            }

        } -ArgumentList $PatchData, $CsRemotePath, $remoteTempDir, $WhatIf, $timestamp

        # Merge remote output into result
        foreach ($line in $remoteResult.Output)       { $result.Output.Add($line) }
        foreach ($pr   in $remoteResult.PatchResults) { $result.PatchResults.Add($pr) }
        foreach ($inst in $remoteResult.CSInstances)  { $result.CSInstances.Add($inst) }

        if (-not $remoteResult.Success) {
            $result.Error         = $remoteResult.Error
            $result.OverallStatus = "ERROR"
        } else {
            $hasError = $result.PatchResults | Where-Object { $_.Status -eq "ERROR" }
            $hasWarn  = $result.PatchResults | Where-Object { $_.Status -eq "WARN"  }
            if ($hasError) { $result.OverallStatus = "ERROR" }
            elseif ($hasWarn) { $result.OverallStatus = "WARN" }
            else { $result.OverallStatus = "OK" }
        }

    } catch {
        $result.Error         = "Remote execution failed: $_"
        $result.OverallStatus = "ERROR"
        $result.Output.Add("  ERROR: $($result.Error)")
    } finally {
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    }

    return $result
}

# ============================================================
# LAUNCH PARALLEL JOBS
# ============================================================
$jobs = [System.Collections.Generic.List[hashtable]]::new()

foreach ($target in $targetServers) {
    while ((Get-Job -State Running).Count -ge $maxParallelJobs) {
        Start-Sleep -Milliseconds 500
    }
    $j = Start-Job -ScriptBlock $deployScriptBlock `
             -ArgumentList $target.Server, $target.Group,
                           @($patchData), $csRemotePath,
                           $Credential, [bool]$WhatIf
    $jobs.Add(@{ Job = $j; Server = $target.Server; Group = $target.Group })
    Write-Log "Queued : [$($target.Group)] $($target.Server)" -Color Gray
}

Write-Log "Deploying to $($targetServers.Count) server(s) in parallel..." -Color Yellow
Write-Log ""

foreach ($entry in $jobs) {
    $finished = $entry.Job | Wait-Job -Timeout $jobTimeoutSec
    if (-not $finished) {
        Write-Log "TIMEOUT: [$($entry.Group)] $($entry.Server)" -Color Red
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

# ============================================================
# CONSOLE OUTPUT
# ============================================================
$zoneSummary = [ordered]@{}
$prevGroup   = $null

foreach ($result in ($results | Sort-Object GroupName, ComputerName)) {
    $grp = $result.GroupName
    if (-not $zoneSummary.Contains($grp)) {
        $zoneSummary[$grp] = @{ OK=0; WARN=0; ERROR=0 }
    }
    $zoneSummary[$grp][$result.OverallStatus]++

    if ($grp -ne $prevGroup) {
        Write-Log "" -Color White
        Write-Log "########################################" -Color Magenta
        Write-Log "# Zone: $grp" -Color Magenta
        Write-Log "########################################" -Color Magenta
        $prevGroup = $grp
    }

    $headerColor = switch ($result.OverallStatus) {
        "ERROR" { "Red" } "WARN" { "Yellow" } default { "Cyan" }
    }

    Write-Log "" -Color White
    Write-Log "========================================" -Color $headerColor
    Write-Log "Zone   : $($result.GroupName)" -Color Magenta
    Write-Log "Server : $($result.ComputerName)  [$($result.OverallStatus)]" -Color $headerColor

    foreach ($line in $result.Output) {
        $color = "White"
        if     ($line -match "ERROR:")               { $color = "Red"     }
        elseif ($line -match "WARN:")                { $color = "Yellow"  }
        elseif ($line -match "\[WHATIF\]")           { $color = "Magenta" }
        elseif ($line -match "\[UPDATE\]")           { $color = "Yellow"  }
        elseif ($line -match "\[NEW\]")              { $color = "Green"   }
        elseif ($line -match "Extracted|Backup saved|Combined backup") { $color = "Green" }
        elseif ($line -match "── Patch:")            { $color = "Cyan"    }
        elseif ($line -match "CS instances:")        { $color = "Cyan"    }
        Write-Log $line -Color $color
    }
    Write-Log "========================================" -Color $headerColor
}

# Zone rollup
Write-Log "" -Color White
Write-Log "======== Zone Rollup ========" -Color Cyan
foreach ($grp in $zoneSummary.Keys) {
    $s   = $zoneSummary[$grp]
    $tot = $s.OK + $s.WARN + $s.ERROR
    $col = if ($s.ERROR -gt 0) { "Red" } elseif ($s.WARN -gt 0) { "Yellow" } else { "Green" }
    Write-Log ("  {0,-40} : {1} OK  {2} WARN  {3} ERROR  (of {4})" -f `
        $grp, $s.OK, $s.WARN, $s.ERROR, $tot) -Color $col
}
Write-Log "=============================" -Color Cyan

# ============================================================
# OPTIONAL SERVICE RESTART
# ============================================================
$successfulServers = @($results | Where-Object { $_.OverallStatus -in @("OK","WARN") -and $_.CSInstances.Count -gt 0 })

if ($successfulServers.Count -gt 0) {
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  Content Server Service Restart" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""

    $hasConsoleForRestart = $true
    try { [void][System.Console]::KeyAvailable } catch { $hasConsoleForRestart = $false }

    if (-not $hasConsoleForRestart) {
        Write-Log "Non-interactive mode — skipping restart prompt." -Color Gray
    } else {
        Write-Host "  Servers with Content Server instances:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $successfulServers.Count; $i++) {
            $r = $successfulServers[$i]
            Write-Host "  [$i] $($r.ComputerName)  ($($r.GroupName))  — instances: $($r.CSInstances -join ', ')" -ForegroundColor White
        }
        Write-Host "  [A] Restart ALL   [S] Skip" -ForegroundColor Yellow
        Write-Host ""

        $restartChoice = (Read-Host "  Choice (A / S / comma-separated numbers e.g. 0,2)").Trim().ToUpper()

        $toRestart = [System.Collections.Generic.List[PSCustomObject]]::new()
        if ($restartChoice -eq "A") {
            $toRestart.AddRange($successfulServers)
        } elseif ($restartChoice -ne "S" -and $restartChoice -ne "") {
            foreach ($part in ($restartChoice -split ",\s*")) {
                if ($part -match "^\d+$") {
                    $idx = [int]$part
                    if ($idx -ge 0 -and $idx -lt $successfulServers.Count) {
                        $toRestart.Add($successfulServers[$idx])
                    }
                }
            }
        }

        foreach ($r in $toRestart) {
            Write-Log "Restarting CS instances on $($r.ComputerName)..." -Color Cyan

            $restartParams = @{
                ComputerName = $r.ComputerName
                ErrorAction  = "Stop"
                ArgumentList = @($r.CSInstances), [bool]$WhatIf
                ScriptBlock  = {
                    param([string[]]$Instances, [bool]$WhatIf)
                    $log = [System.Collections.Generic.List[string]]::new()
                    foreach ($svcName in $Instances) {
                        if ($WhatIf) {
                            $log.Add("[WHATIF] Would restart: $svcName")
                            continue
                        }
                        try {
                            Restart-Service -Name $svcName -Force -ErrorAction Stop
                            $log.Add("Restarted: $svcName [OK]")
                        } catch {
                            $log.Add("FAILED to restart $svcName : $_")
                        }
                    }
                    return $log
                }
            }
            if ($Credential) { $restartParams["Credential"] = $Credential }

            try {
                $restartLog = Invoke-Command @restartParams
                foreach ($l in $restartLog) {
                    $col = if ($l -match "FAILED") { "Red" } elseif ($l -match "WHATIF") { "Magenta" } else { "Green" }
                    Write-Log "  $($r.ComputerName): $l" -Color $col
                }
            } catch {
                Write-Log "  ERROR restarting services on $($r.ComputerName): $_" -Color Red
            }
        }
    }
}

# ============================================================
# HTML REPORT
# ============================================================
$zoneRollupHtml = ""
foreach ($grp in $zoneSummary.Keys) {
    $s   = $zoneSummary[$grp]
    $cls = if ($s.ERROR -gt 0) { "critical" } elseif ($s.WARN -gt 0) { "warn" } else { "ok" }
    $zoneRollupHtml += "<div class='zone-pill $cls'>$grp &nbsp; OK:$($s.OK) WARN:$($s.WARN) ERROR:$($s.ERROR)</div>"
}

$patchSummaryHtml = ""
foreach ($pm in $patchManifests) {
    $patchSummaryHtml += "<div class='patch-pill'>&#x1F4E6; $($pm.Name) &nbsp;<span class='muted'>$($pm.SizeMB) MB &nbsp; $($pm.Entries.Count) files</span></div>"
}

$tableRows = ""
foreach ($result in ($results | Sort-Object GroupName, ComputerName)) {
    $serverCls = switch ($result.OverallStatus) { "ERROR" { "critical" } "WARN" { "warn" } default { "ok" } }
    $srvId     = "srv_$($result.ComputerName -replace '[^a-zA-Z0-9]','_')"

    $patchRows = ""
    if ($result.Error) {
        $patchRows = "<tr class='patch-row critical'><td colspan='6'>$($result.Error)</td></tr>"
    } elseif ($result.PatchResults -and $result.PatchResults.Count -gt 0) {
        foreach ($pr in $result.PatchResults) {
            $prCls    = switch ($pr.Status) { "ERROR" { "critical" } "WARN" { "warn" } default { "ok" } }
            $patchRows += "
            <tr class='patch-row $prCls'>
              <td><code>$($pr.PatchName)</code></td>
              <td class='center'>$($pr.FilesInZip)</td>
              <td class='center updated'>$($pr.FilesUpdated)</td>
              <td class='center new'>$($pr.FilesNew)</td>
              <td class='center backed'>$($pr.FilesBacked)</td>
              <td><span class='backup-name'>$($pr.BackupFile)</span></td>
            </tr>"
        }
    } else {
        $patchRows = "<tr class='patch-row warn'><td colspan='6'>No patch results recorded.</td></tr>"
    }

    $instancesHtml = if ($result.CSInstances -and $result.CSInstances.Count -gt 0) {
        ($result.CSInstances | ForEach-Object { "<span class='instance-tag'>$_</span>" }) -join " "
    } else { "<span class='muted'>none detected</span>" }

    $tableRows += "
    <tr class='server-header $serverCls' onclick='toggle(""$srvId"")'>
      <td colspan='6'>
        &#x25BC; <strong>$($result.ComputerName)</strong>
        <span class='zone-tag'>$($result.GroupName)</span>
        <span class='status-badge $serverCls'>$($result.OverallStatus)</span>
        <br><small><span class='muted'>CS Instances: </span>$instancesHtml</small>
      </td>
    </tr>
    <tbody id='$srvId' class='collapsible'>
      <tr class='col-header'>
        <th>Patch File</th><th>Files in ZIP</th><th>Updated</th>
        <th>New</th><th>Backed Up</th><th>Backup File</th>
      </tr>
      $patchRows
    </tbody>"
}

$html = @"
<!DOCTYPE html>
<html><head><meta charset='UTF-8'>
<title>CS Patch Deployment Report - $timestamp</title>
<style>
  body{font-family:Consolas,monospace;background:#1e1e1e;color:#d4d4d4;margin:20px}
  h1{color:#4ec9b0} h2{color:#9cdcfe}
  table{border-collapse:collapse;width:100%;margin-top:16px}
  th{background:#2d2d2d;color:#9cdcfe;padding:8px 12px;text-align:left;border:1px solid #3c3c3c;font-size:12px}
  td{padding:6px 12px;border:1px solid #3c3c3c;font-size:12px;vertical-align:top}
  .center{text-align:center}
  .server-header td{background:#1a3a5c;color:#9cdcfe;font-size:13px;cursor:pointer;padding:8px 14px}
  .server-header.warn td{background:#2a2800;border-left:4px solid #dcdcaa}
  .server-header.critical td{background:#2a1010;border-left:4px solid #f44747}
  .server-header.ok td{border-left:4px solid #4ec9b0}
  .col-header th{background:#252540;color:#c586c0;font-size:11px}
  .patch-row.ok td{color:#d4d4d4}
  .patch-row.warn td{background:#1e1a00;color:#dcdcaa}
  .patch-row.critical td{background:#1e0a0a;color:#f44747}
  tr:hover td{background:#252526}
  .collapsible{display:table-row-group}
  .updated{color:#dcdcaa;font-weight:bold}
  .new{color:#4ec9b0;font-weight:bold}
  .backed{color:#c586c0;font-weight:bold}
  .zone-pill{display:inline-block;margin:4px 6px;padding:6px 14px;border-radius:14px;font-size:13px;font-weight:bold}
  .zone-pill.ok{background:#1e3a2f;color:#4ec9b0;border:1px solid #4ec9b0}
  .zone-pill.warn{background:#3a3000;color:#dcdcaa;border:1px solid #dcdcaa}
  .zone-pill.critical{background:#3a1e1e;color:#f44747;border:1px solid #f44747}
  .patch-pill{display:inline-block;margin:4px 6px;padding:6px 14px;border-radius:14px;font-size:12px;background:#252540;color:#9cdcfe;border:1px solid #3c3c3c}
  .zone-tag{display:inline-block;background:#1a3a5c;color:#9cdcfe;border-radius:4px;padding:1px 8px;margin-left:10px;font-size:11px}
  .status-badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:bold;margin-left:8px}
  .status-badge.ok{background:#1e3a2f;color:#4ec9b0}
  .status-badge.warn{background:#3a3000;color:#dcdcaa}
  .status-badge.critical{background:#3a1e1e;color:#f44747}
  .instance-tag{display:inline-block;background:#252540;color:#c586c0;border-radius:4px;padding:1px 6px;margin:1px;font-size:10px}
  .backup-name{font-size:10px;color:#6a9955}
  .summary{background:#252526;padding:12px;border-radius:6px;margin-bottom:18px}
  .muted{color:#6a9955;font-size:11px}
  code{background:#2d2d2d;padding:1px 5px;border-radius:3px;color:#ce9178}
</style></head><body>
<h1>&#x1F4E6; Content Server Patch Deployment Report</h1>
<div class='summary'>
  <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  &nbsp;|&nbsp; <strong>Servers:</strong> $($targetServers.Count)
  &nbsp;|&nbsp; <strong>Patches:</strong> $($patchManifests.Count)
  $(if($WhatIf){"&nbsp;|&nbsp; <strong style='color:#dcdcaa'>[WHATIF MODE]</strong>"})
</div>
<h2>Patches Deployed</h2>
<div>$patchSummaryHtml</div>
<h2>Zone Summary</h2>
<div>$zoneRollupHtml</div>
<h2>Deployment Detail</h2>
<table>
<tbody>$tableRows</tbody>
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

# ============================================================
# FOOTER
# ============================================================
Write-Log "" -Color White
Write-Log "========================================" -Color Cyan
Write-Log "Completed : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Color Cyan
Write-Log "HTML      : $htmlFile" -Color Green
Write-Log "Log       : $logFile"  -Color Green
Write-Log "========================================" -Color Cyan

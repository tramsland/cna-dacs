#==================================================================================
#
#   SCRIPT: Test-RemoteConnections.ps1
#
#   PURPOSE:
#   One-off diagnostic script to test all remote connection methods (WinRM, DCOM,
#   UNC) and validate that each core operation works end-to-end against a target
#   server. Run from Admin console. No changes are committed without confirmation.
#
#   OPERATIONS TESTED:
#     1. Connection tier detection  (WinRM / DCOM / UNC)
#     2. Service discovery          (wildcard description lookup)
#     3. Home directory mapping     (Content Server, Tomcat, System Center)
#     4. Backup                     (compress discovered directories)
#     5. Service stop/start         (by resolved service name)
#     6. System Center              (uninstall + reinstall MSI remotely)
#     7. Tomcat file overwrite      (remote file copy, no uninstall)
#
#   USAGE:
#     Run the script and enter a target FQDN when prompted.
#     Each test section reports PASS / WARN / FAIL with details.
#     Destructive operations (backup, SC reinstall, Tomcat overwrite) require
#     explicit YES confirmation before executing.
#
#   CONNECTION FALLBACK:
#     Tier 1 - WinRM  (Invoke-Command / PSSession, port 5985)
#     Tier 2 - DCOM   (CIM session + Win32_Process, port 135)
#     Tier 3 - UNC    (admin share file access only, no remote execution)
#
#==================================================================================

#region Bootstrap
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  [ERROR] Must be run as Administrator." -ForegroundColor Red
    Write-Host "          Right-click PowerShell -> Run as Administrator." -ForegroundColor Yellow
    Write-Host ""
    pause; exit 1
}
#endregion

#region Helpers
function Write-Section {
    param([string]$Title)
    $line = '-' * 70
    Write-Host ""
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor DarkCyan
}

function Write-Result {
    param([string]$Label, [string]$Status, [string]$Detail = '')
    $color = switch ($Status) {
        'PASS'   { 'Green'  }
        'WARN'   { 'Yellow' }
        'FAIL'   { 'Red'    }
        'INFO'   { 'Gray'   }
        default  { 'White'  }
    }
    $pad  = ' ' * [math]::Max(0, 42 - $Label.Length)
    $line = "  $Label$pad[$Status]"
    if ($Detail) { $line += "  $Detail" }
    Write-Host $line -ForegroundColor $color
}

function Confirm-Action {
    param([string]$Prompt)
    Write-Host ""
    Write-Host "  >> $Prompt" -ForegroundColor Magenta
    Write-Host "     Type YES to proceed, anything else to skip: " -ForegroundColor White -NoNewline
    $ans = Read-Host
    return ($ans.Trim().ToUpper() -eq 'YES')
}

$script:Results = [System.Collections.Generic.List[pscustomobject]]::new()
function Add-Result {
    param([string]$Section, [string]$Label, [string]$Status, [string]$Detail = '')
    $script:Results.Add([pscustomobject]@{
        Section = $Section; Label = $Label; Status = $Status; Detail = $Detail
    })
    Write-Result -Label $Label -Status $Status -Detail $Detail
}
#endregion

#region Input
Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "   CNA-DACS Remote Connection Diagnostic" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Target server FQDN (e.g. server01.dacs.dla.mil): " -ForegroundColor White -NoNewline
$TargetServer = (Read-Host).Trim()
if (-not $TargetServer) { Write-Host "  No server entered. Exiting." -ForegroundColor Red; exit 1 }

Write-Host "  NewVersion folder path for Tomcat test (leave blank to skip): " -ForegroundColor White -NoNewline
$NewVersionPath = (Read-Host).Trim()

Write-Host "  SC Agent MSI URL (leave blank for default patch.dacs.dla.mil): " -ForegroundColor White -NoNewline
$MsiUrlInput = (Read-Host).Trim()
$MsiUrl  = if ($MsiUrlInput) { $MsiUrlInput } else { 'https://patch.dacs.dla.mil/downloadAgent/?ostype=win&filetype=installer' }
$MsiName = 'OpenText_SystemCenter_Agent.msi'

Write-Host ""
Write-Host "  Target  : $TargetServer"  -ForegroundColor White
Write-Host "  MSI URL : $MsiUrl"        -ForegroundColor Gray
if ($NewVersionPath) { Write-Host "  Tomcat  : $NewVersionPath" -ForegroundColor Gray }
#endregion

#============================================================
# SECTION 1 — CONNECTIVITY
#============================================================
Write-Section "1. CONNECTIVITY TESTS"

# 1a — Ping
$pingOk = Test-Connection -ComputerName $TargetServer -Count 2 -Quiet
Add-Result '1. Connectivity' 'ICMP Ping' `
    $(if ($pingOk) {'PASS'} else {'WARN'}) `
    $(if ($pingOk) {'Reachable'} else {'No ICMP response (may still work)'})

# 1b — WinRM
$winrmOk     = $false
$WinRMSession = $null
try {
    $WinRMSession = New-PSSession -ComputerName $TargetServer -ErrorAction Stop
    $winrmOk      = $true
    Add-Result '1. Connectivity' 'WinRM (port 5985)' 'PASS' 'PSSession established'
}
catch {
    Add-Result '1. Connectivity' 'WinRM (port 5985)' 'FAIL' $_.Exception.Message
}

# 1c — DCOM / CIM
$dcomOk     = $false
$CimSession = $null
try {
    $opt        = New-CimSessionOption -Protocol Dcom
    $CimSession = New-CimSession -ComputerName $TargetServer -SessionOption $opt -ErrorAction Stop
    $dcomOk     = $true
    Add-Result '1. Connectivity' 'DCOM / CIM (port 135)' 'PASS' 'CimSession established'
}
catch {
    Add-Result '1. Connectivity' 'DCOM / CIM (port 135)' 'FAIL' $_.Exception.Message
}

# 1d — UNC e$
$uncBase = "\\$TargetServer\e$"
$uncEOk  = Test-Path $uncBase
Add-Result '1. Connectivity' "UNC e$ share" `
    $(if ($uncEOk) {'PASS'} else {'FAIL'}) `
    $(if ($uncEOk) {'Share reachable'} else {'Cannot reach e$'})

# 1e — UNC c$ (needed for DCOM temp staging)
$uncC   = "\\$TargetServer\c$"
$uncCOk = Test-Path $uncC
Add-Result '1. Connectivity' "UNC c$ share" `
    $(if ($uncCOk) {'PASS'} else {'WARN'}) `
    $(if ($uncCOk) {'Share reachable'} else {'Cannot reach c$ - DCOM exec staging may fail'})

$ConnectionTier = if ($winrmOk) {'WinRM'} elseif ($dcomOk) {'DCOM'} elseif ($uncEOk) {'UNC'} else {'NONE'}
Add-Result '1. Connectivity' 'Best available tier' 'INFO' $ConnectionTier

if ($ConnectionTier -eq 'NONE') {
    Write-Host ""
    Write-Host "  [FATAL] No connection method succeeded. Cannot continue." -ForegroundColor Red
    exit 1
}

#region Invoke-Remote helper
# Provides WinRM -> DCOM fallback for running scriptblocks on the target.
# UNC-only connections cannot execute code and will throw.
function Invoke-Remote {
    param(
        [scriptblock]$Block,
        [object[]]$Args = @(),
        [int]$TimeoutSec = 120
    )

    # --- WinRM ---
    if ($winrmOk) {
        return Invoke-Command -Session $WinRMSession -ScriptBlock $Block -ArgumentList $Args
    }

    # --- DCOM: write ps1 via UNC, launch via Win32_Process, read output ---
    if ($dcomOk) {
        $guid   = [guid]::NewGuid().ToString('N')
        $ps1Unc = "\\$TargetServer\c$\Windows\Temp\diag_$guid.ps1"
        $outUnc = "\\$TargetServer\c$\Windows\Temp\diag_out_$guid.txt"
        $ps1Rem = "C:\Windows\Temp\diag_$guid.ps1"
        $outRem = "C:\Windows\Temp\diag_out_$guid.txt"

        $argLines = for ($i = 0; $i -lt $Args.Count; $i++) {
            "`$a$i = $(ConvertTo-Json $Args[$i] -Depth 5 -Compress)"
        }
        $argPass = if ($Args.Count -gt 0) {
            (0..($Args.Count-1) | ForEach-Object { "`$a$_" }) -join ','
        } else { '' }
        $body = "$(($argLines) -join "`n")`n& {`n$($Block.ToString())`n} $argPass 2>&1 | Out-File '$outRem' -Encoding utf8"
        Set-Content -Path $ps1Unc -Value $body -Encoding UTF8

        $mc = [wmiclass]"\\$TargetServer\root\cimv2:Win32_Process"
        $r  = $mc.Create("powershell.exe -NonInteractive -ExecutionPolicy Bypass -File `"$ps1Rem`"")
        if ($r.ReturnValue -ne 0) {
            Remove-Item $ps1Unc -Force -ErrorAction SilentlyContinue
            throw "Win32_Process.Create failed (rc=$($r.ReturnValue))"
        }
        $pid2 = $r.ProcessId; $elapsed = 0
        do {
            Start-Sleep 2; $elapsed += 2
            $running = Get-WmiObject -Class Win32_Process -ComputerName $TargetServer `
                           -Filter "ProcessId=$pid2" -ErrorAction SilentlyContinue
        } while ($running -and $elapsed -lt $TimeoutSec)

        $out = Get-Content $outUnc -ErrorAction SilentlyContinue
        Remove-Item $outUnc,$ps1Unc -Force -ErrorAction SilentlyContinue
        return $out
    }

    throw "No remote execution available (UNC-only connection)"
}
#endregion

#============================================================
# SECTION 2 — SERVICE DISCOVERY + HOME DIRECTORY MAPPING
#============================================================
Write-Section "2. SERVICE DISCOVERY + HOME DIRECTORY MAPPING"

$script:DiscoveredServices = $null

$discoverBlock = {
    $out = [System.Collections.Generic.List[pscustomobject]]::new()

    function Find-AncestorDir {
        param([string]$Start, [string]$Name, [int]$Max = 8)
        $d = $Start
        for ($i = 0; $i -lt $Max; $i++) {
            if ([IO.Path]::GetFileName($d) -ieq $Name) { return $d }
            $child = Join-Path $d $Name
            if (Test-Path $child -PathType Container) { return $child }
            $p = Split-Path $d -Parent
            if (-not $p -or $p -eq $d) { break }
            $d = $p
        }
        return $null
    }

    function Get-ExeDir {
        param([string]$PathName)
        if (-not $PathName) { return $null }
        $exe = $PathName -replace '^"([^"]+)".*$','$1' `
                         -replace '^([^\s"]+\.exe).*$','$1'
        return Split-Path $exe -Parent
    }

    try { $allSvcs = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop }
    catch { $allSvcs = Get-WmiObject -Class Win32_Service -ErrorAction Stop }

    # ---- Content Server (not Admin) ----
    $csSvc = $allSvcs | Where-Object {
        ($_.Description -like '*Content Server*' -or $_.Name -like '*ContentServer*') -and
        $_.Description -notlike '*Content Server Admin*' -and
        $_.Name -notlike '*Admin*'
    } | Select-Object -First 1

    if ($csSvc) {
        $exeDir  = Get-ExeDir $csSvc.PathName
        $homeDir = if ($exeDir) { Find-AncestorDir $exeDir 'contentserver' } else { $null }
        $out.Add([pscustomobject]@{
            Role = 'ContentServer'; Name = $csSvc.Name
            DisplayName = $csSvc.DisplayName; Status = $csSvc.State
            PathName = $csSvc.PathName; HomeDir = $homeDir
        })
    }

    # ---- Content Server Admin ----
    $csAdminSvc = $allSvcs | Where-Object {
        $_.Description -like '*Content Server Admin*' -or
        ($_.Name -like '*Admin*' -and $_.Description -like '*Content Server*')
    } | Select-Object -First 1

    if ($csAdminSvc) {
        $out.Add([pscustomobject]@{
            Role = 'ContentServerAdmin'; Name = $csAdminSvc.Name
            DisplayName = $csAdminSvc.DisplayName; Status = $csAdminSvc.State
            PathName = $csAdminSvc.PathName; HomeDir = $null
        })
    }

    # ---- Tomcat (all instances) ----
    $tcSvcs = @($allSvcs | Where-Object {
        $_.DisplayName -like '*Apache Tomcat*' -or
        $_.DisplayName -like '*Tomcat*' -or
        $_.Name        -like '*Tomcat*'
    })
    foreach ($tc in $tcSvcs) {
        $exeDir  = Get-ExeDir $tc.PathName
        $homeDir = $null
        if ($exeDir) {
            # Tomcat root is typically 2 levels up: root\bin\exe
            $root = Split-Path (Split-Path $exeDir -Parent) -Parent
            if ((Test-Path "$root\bin") -and (Test-Path "$root\lib")) {
                $homeDir = $root
            }
        }
        if (-not $homeDir) {
            foreach ($c in @('E:\Customers\dacs\shared\tomcat10','E:\Customers\dacs\shared\tomcat')) {
                if ((Test-Path "$c\bin") -and (Test-Path "$c\lib")) { $homeDir = $c; break }
            }
        }
        $out.Add([pscustomobject]@{
            Role = 'Tomcat'; Name = $tc.Name
            DisplayName = $tc.DisplayName; Status = $tc.State
            PathName = $tc.PathName; HomeDir = $homeDir
        })
    }

    # ---- System Center Agent ----
    $scSvc = $allSvcs | Where-Object {
        $_.Name        -like '*OTSystemCenter*' -or
        $_.DisplayName -like '*System Center*'  -or
        $_.DisplayName -like '*OpenText System*'
    } | Select-Object -First 1

    if ($scSvc) {
        $homeDir = @(
            'E:\Customers\dacs\shared\systemcenteragent',
            'C:\Program Files\OpenText\SystemCenter',
            'C:\Program Files (x86)\OpenText\SystemCenter'
        ) | Where-Object { Test-Path $_ } | Select-Object -First 1

        $out.Add([pscustomobject]@{
            Role = 'SystemCenter'; Name = $scSvc.Name
            DisplayName = $scSvc.DisplayName; Status = $scSvc.State
            PathName = $scSvc.PathName; HomeDir = $homeDir
        })
    }

    return ($out | ConvertTo-Json -Depth 5)
}

try {
    $rawJson = Invoke-Remote -Block $discoverBlock
    $jsonStr = ($rawJson -join '') -replace '^\s+|\s+$',''
    $discovered = $jsonStr | ConvertFrom-Json

    if ($discovered -and @($discovered).Count -gt 0) {
        $script:DiscoveredServices = @($discovered)
        Add-Result '2. Discovery' 'Remote execution' 'PASS' "Results received via $ConnectionTier"

        foreach ($svc in $script:DiscoveredServices) {
            Add-Result '2. Discovery' "$($svc.Role) - Name"    'INFO' $svc.Name
            Add-Result '2. Discovery' "$($svc.Role) - Status"  'INFO' $svc.Status
            Add-Result '2. Discovery' "$($svc.Role) - HomeDir" `
                $(if ($svc.HomeDir) {'PASS'} else {'WARN'}) `
                $(if ($svc.HomeDir) { $svc.HomeDir } else { 'Not resolved — check PathName or candidates' })
        }
    } else {
        Add-Result '2. Discovery' 'Service discovery' 'WARN' 'No matching services found on target'
    }
}
catch {
    Add-Result '2. Discovery' 'Remote execution' 'FAIL' $_.Exception.Message
}

#============================================================
# SECTION 3 — SERVICE STOP / START
#============================================================
Write-Section "3. SERVICE STOP / START (wildcard-discovered names)"

if (-not $script:DiscoveredServices) {
    Add-Result '3. Svc Stop/Start' 'Stop/Start test' 'WARN' 'Skipped — no services discovered'
} else {
    $svcNames = @($script:DiscoveredServices | Select-Object -ExpandProperty Name | Where-Object { $_ })

    # Dry-run: read current state
    $svcCheckBlock = {
        param([string[]]$Names)
        $out = @()
        foreach ($n in $Names) {
            $s = Get-Service -Name $n -ErrorAction SilentlyContinue
            $out += if ($s) { "$n|$($s.Status)|OK" } else { "$n|NotFound|WARN" }
        }
        return $out
    }
    try {
        $checks = @(Invoke-Remote -Block $svcCheckBlock -Args @(,$svcNames))
        foreach ($line in $checks) {
            if ($line -is [string] -and $line -match '\|') {
                $p = $line -split '\|'
                Add-Result '3. Svc Stop/Start' "Read state: $($p[0])" `
                    $(if ($p[2] -eq 'OK') {'PASS'} else {'WARN'}) "Status=$($p[1])"
            }
        }
    }
    catch {
        Add-Result '3. Svc Stop/Start' 'Service state read' 'FAIL' $_.Exception.Message
    }

    # Live stop/start
    if (Confirm-Action "LIVE TEST: Stop then immediately restart all discovered services on $TargetServer?") {
        $stopStartBlock = {
            param([string[]]$Names, [int]$TimeoutSec)
            $log     = [System.Collections.Generic.List[string]]::new()
            $stopped = [System.Collections.Generic.List[string]]::new()
            $ok      = $true

            function WaitSvc { param($n,$state,$t)
                $svc = Get-Service -Name $n -ErrorAction Stop
                $svc.WaitForStatus($state, [TimeSpan]::FromSeconds($t))
            }

            foreach ($n in $Names) {
                $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
                if (-not $svc)               { $log.Add("WARN $n not found"); continue }
                if ($svc.Status -ne 'Running') { $log.Add("INFO $n already stopped"); continue }
                try {
                    Stop-Service -Name $n -Force -ErrorAction Stop
                    WaitSvc $n 'Stopped' $TimeoutSec
                    $stopped.Add($n)
                    $log.Add("PASS Stopped $n")
                }
                catch { $log.Add("FAIL Stop ${n}: $_"); $ok = $false }
            }

            $arr = $stopped.ToArray(); [array]::Reverse($arr)
            foreach ($n in $arr) {
                try {
                    Start-Service -Name $n -ErrorAction Stop
                    WaitSvc $n 'Running' $TimeoutSec
                    $log.Add("PASS Started $n")
                }
                catch { $log.Add("FAIL Start ${n}: $_"); $ok = $false }
            }
            $log.Add("RESULT $(if ($ok) {'SUCCESS'} else {'PARTIAL_FAILURE'})")
            return $log
        }
        try {
            $svcLog = @(Invoke-Remote -Block $stopStartBlock -Args @(,$svcNames, 60) -TimeoutSec 300)
            foreach ($line in $svcLog) {
                if ($line -is [string]) {
                    $p = $line -split '\s+', 2
                    $s = switch ($p[0]) { 'PASS' {'PASS'} 'FAIL' {'FAIL'} 'WARN' {'WARN'} default {'INFO'} }
                    Add-Result '3. Svc Stop/Start' 'Live test' $s ($p[1])
                }
            }
        }
        catch {
            Add-Result '3. Svc Stop/Start' 'Live stop/start' 'FAIL' $_.Exception.Message
        }
    } else {
        Add-Result '3. Svc Stop/Start' 'Live test' 'INFO' 'Skipped by user'
    }
}

#============================================================
# SECTION 4 — BACKUP (compress discovered home directories)
#============================================================
Write-Section "4. BACKUP — Compress discovered home directories"

$homeDirs = @()
if ($script:DiscoveredServices) {
    $homeDirs = @($script:DiscoveredServices |
        Where-Object { $_.HomeDir } |
        Select-Object -ExpandProperty HomeDir -Unique)
}

if ($homeDirs.Count -eq 0) {
    Add-Result '4. Backup' 'Backup' 'WARN' 'No home directories resolved — nothing to back up'
} else {
    Write-Host ""
    Write-Host "  Directories that will be compressed:" -ForegroundColor White
    foreach ($d in $homeDirs) { Write-Host "    $d" -ForegroundColor Gray }

    if (Confirm-Action "LIVE TEST: Compress each home directory to a .zip in its parent folder on $TargetServer?") {
        $backupBlock = {
            param([string[]]$Dirs)
            $log = [System.Collections.Generic.List[string]]::new()
            foreach ($d in $Dirs) {
                if (-not (Test-Path $d)) { $log.Add("FAIL Not found: $d"); continue }
                $parent  = Split-Path $d -Parent
                $leaf    = Split-Path $d -Leaf
                $zipPath = Join-Path $parent "${leaf}_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
                try {
                    Compress-Archive -Path $d -DestinationPath $zipPath -Force
                    $sizeMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
                    $log.Add("PASS $d -> $zipPath ($sizeMB MB)")
                }
                catch { $log.Add("FAIL Compress ${d}: $_") }
            }
            return $log
        }
        try {
            $backupLog = @(Invoke-Remote -Block $backupBlock -Args @(,$homeDirs) -TimeoutSec 600)
            foreach ($line in $backupLog) {
                if ($line -is [string]) {
                    $p = $line -split '\s+', 2
                    $s = if ($p[0] -eq 'PASS') {'PASS'} else {'FAIL'}
                    Add-Result '4. Backup' 'Directory backup' $s ($p[1])
                }
            }
        }
        catch {
            Add-Result '4. Backup' 'Remote backup' 'FAIL' $_.Exception.Message
        }
    } else {
        Add-Result '4. Backup' 'Backup' 'INFO' 'Skipped by user'
    }
}

#============================================================
# SECTION 5 — SYSTEM CENTER AGENT: UNINSTALL + REINSTALL
#============================================================
Write-Section "5. SYSTEM CENTER AGENT — Remote Uninstall + Reinstall"

# 5a — Detect installed version
$scDetectBlock = {
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($rp in $regPaths) {
        if (-not (Test-Path $rp)) { continue }
        foreach ($key in (Get-ChildItem $rp -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
            if ($p.DisplayName -like '*System Center*' -or $p.DisplayName -like '*OTS*') {
                return "$($p.DisplayName)|$($p.DisplayVersion)|$($p.PSChildName)"
            }
        }
    }
    try {
        $prod = Get-CimInstance -ClassName Win32_Product -ErrorAction Stop |
                Where-Object { $_.Name -like '*System Center*' -or $_.Name -like '*OTS*' } |
                Select-Object -First 1
        if ($prod) { return "$($prod.Name)|$($prod.Version)|$($prod.IdentifyingNumber)" }
    } catch { }
    return 'NOT_FOUND||'
}

$scName = $scVer = $scCode = $null
try {
    $scRaw   = Invoke-Remote -Block $scDetectBlock
    $scStr   = ($scRaw -join '').Trim()
    $scParts = $scStr -split '\|'
    $scName  = $scParts[0]; $scVer = $scParts[1]; $scCode = $scParts[2]

    if ($scName -eq 'NOT_FOUND') {
        Add-Result '5. SystemCenter' 'SC Agent installed' 'WARN' 'Not found — will attempt fresh install'
    } else {
        Add-Result '5. SystemCenter' 'SC Agent installed'    'PASS' $scName
        Add-Result '5. SystemCenter' 'SC Agent version'      'INFO' $scVer
        Add-Result '5. SystemCenter' 'SC Agent product code' 'INFO' $scCode
    }
}
catch {
    Add-Result '5. SystemCenter' 'SC Agent detection' 'FAIL' $_.Exception.Message
}

# 5b — Test MSI URL (HEAD request from admin console)
try {
    $resp = Invoke-WebRequest -Uri $MsiUrl -Method Head -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    Add-Result '5. SystemCenter' 'MSI URL reachable (HEAD)' 'PASS' "HTTP $($resp.StatusCode)"
}
catch {
    Add-Result '5. SystemCenter' 'MSI URL reachable (HEAD)' 'WARN' $_.Exception.Message
}

# 5c — Test UNC staging path write
$uncTemp = "\\$TargetServer\c$\Windows\Temp\SCA_DiagTest"
try {
    New-Item -ItemType Directory -Path $uncTemp -Force | Out-Null
    Add-Result '5. SystemCenter' 'UNC staging path writable' 'PASS' $uncTemp
    Remove-Item $uncTemp -Force -ErrorAction SilentlyContinue
}
catch {
    Add-Result '5. SystemCenter' 'UNC staging path writable' 'FAIL' $_.Exception.Message
}

# 5d — Live uninstall + reinstall
if (Confirm-Action "LIVE TEST: Download MSI, push to $TargetServer, uninstall current SC Agent, reinstall?`n     (All services stopped and restarted. This is the real operation.)") {

    $tmpDir  = Join-Path $env:TEMP "SCA_Diag_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $msiPath = Join-Path $tmpDir $MsiName
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    Write-Host "  Downloading MSI from $MsiUrl ..." -ForegroundColor Yellow
    try {
        (New-Object System.Net.WebClient).DownloadFile($MsiUrl, $msiPath)
        $sizeMB = [math]::Round((Get-Item $msiPath).Length / 1MB, 2)
        Add-Result '5. SystemCenter' 'MSI download' 'PASS' "$msiPath ($sizeMB MB)"
    }
    catch {
        Add-Result '5. SystemCenter' 'MSI download' 'FAIL' $_.Exception.Message
        $msiPath = $null
    }

    if ($msiPath) {
        # Push MSI via UNC
        $remoteDeployDir = "\\$TargetServer\c$\Windows\Temp\SCA_Deploy"
        $remoteMsiUnc    = "$remoteDeployDir\$MsiName"
        $remoteMsiLocal  = "C:\Windows\Temp\SCA_Deploy\$MsiName"
        try {
            if (-not (Test-Path $remoteDeployDir)) {
                New-Item -ItemType Directory -Path $remoteDeployDir -Force | Out-Null
            }
            Copy-Item -Path $msiPath -Destination $remoteMsiUnc -Force
            Add-Result '5. SystemCenter' 'MSI pushed via UNC' 'PASS' $remoteMsiUnc
        }
        catch {
            Add-Result '5. SystemCenter' 'MSI pushed via UNC' 'FAIL' $_.Exception.Message
            $remoteMsiLocal = $null
        }

        if ($remoteMsiLocal) {
            $scInstallBlock = {
                param(
                    [string]$MsiPath,
                    [string]$ProductCode,
                    [string]$InstallDir,
                    [string]$HttpPort,
                    [string]$ServerName,
                    [string[]]$SvcNames,
                    [int]$TimeoutSec
                )
                $log = [System.Collections.Generic.List[string]]::new()
                $ok  = $true

                function WaitSvc { param($n,$state,$t)
                    (Get-Service -Name $n -ErrorAction Stop).WaitForStatus(
                        $state, [TimeSpan]::FromSeconds($t))
                }

                $stopped = [System.Collections.Generic.List[string]]::new()
                try {
                    # Stop all discovered services
                    foreach ($n in $SvcNames) {
                        $svc = Get-Service -Name $n -ErrorAction SilentlyContinue
                        if (-not $svc -or $svc.Status -ne 'Running') {
                            $log.Add("INFO $n not running — skip stop")
                            continue
                        }
                        try {
                            Stop-Service -Name $n -Force -ErrorAction Stop
                            WaitSvc $n 'Stopped' $TimeoutSec
                            $stopped.Add($n)
                            $log.Add("PASS Stopped $n")
                        }
                        catch { $log.Add("WARN Could not stop ${n}: $_") }
                    }

                    # Uninstall current agent
                    if ($ProductCode -and $ProductCode.Trim() -ne '') {
                        if (-not (Test-Path 'C:\Logs')) { New-Item -ItemType Directory -Path 'C:\Logs' -Force | Out-Null }
                        $unLog = "C:\Logs\sc_uninstall_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                        $proc  = Start-Process 'msiexec.exe' `
                            -ArgumentList "/qn /l*vx `"$unLog`" /x `"$ProductCode`"" `
                            -Wait -PassThru
                        if ($proc.ExitCode -eq 0) { $log.Add("PASS Uninstall complete (rc=0)") }
                        else {
                            $log.Add("FAIL Uninstall rc=$($proc.ExitCode) see $unLog")
                            $ok = $false
                        }
                    } else {
                        $log.Add("WARN No product code — skipping uninstall (fresh install)")
                    }

                    # Clear install directory
                    if ($InstallDir -and (Test-Path $InstallDir)) {
                        Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue |
                            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                        $log.Add("INFO Cleared $InstallDir")
                    }

                    # Install new agent
                    if (-not (Test-Path $MsiPath)) { throw "MSI not found at $MsiPath" }
                    if (-not (Test-Path 'C:\Logs')) { New-Item -ItemType Directory -Path 'C:\Logs' -Force | Out-Null }
                    $instLog  = "C:\Logs\sc_install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                    $instArgs = "/qn /l*vx `"$instLog`" /i `"$MsiPath`" " +
                                "HTTP_PORT_NUMBER=`"$HttpPort`" SERVER_NAME=`"$ServerName`""
                    $proc = Start-Process 'msiexec.exe' -ArgumentList $instArgs -Wait -PassThru
                    if ($proc.ExitCode -eq 0) {
                        $log.Add("PASS Install complete. Log: $instLog")
                    } else {
                        $log.Add("FAIL Install rc=$($proc.ExitCode) see $instLog")
                        $ok = $false
                    }
                }
                catch { $log.Add("FAIL $_"); $ok = $false }
                finally {
                    # Always restart in reverse order
                    $arr = $stopped.ToArray(); [array]::Reverse($arr)
                    foreach ($n in $arr) {
                        try {
                            Start-Service -Name $n -ErrorAction Stop
                            WaitSvc $n 'Running' $TimeoutSec
                            $log.Add("PASS Started $n")
                        }
                        catch { $log.Add("FAIL Start ${n}: $_"); $ok = $false }
                    }
                }
                $log.Add("RESULT $(if ($ok) {'SUCCESS'} else {'FAILURE'})")
                return $log
            }

            $allSvcNames = @($script:DiscoveredServices |
                Select-Object -ExpandProperty Name | Where-Object { $_ })

            try {
                $scLog = @(Invoke-Remote -Block $scInstallBlock -Args @(
                    $remoteMsiLocal,
                    $scCode,
                    'E:\Customers\dacs\shared\systemcenteragent',
                    '443',
                    'patch.dacs.dla.mil',
                    $allSvcNames,
                    60
                ) -TimeoutSec 600)

                foreach ($line in $scLog) {
                    if ($line -is [string]) {
                        $p = $line -split '\s+', 2
                        $s = switch ($p[0]) {'PASS' {'PASS'} 'FAIL' {'FAIL'} 'WARN' {'WARN'} default {'INFO'}}
                        Add-Result '5. SystemCenter' "SC: $($p[1])" $s ''
                    }
                }
            }
            catch {
                Add-Result '5. SystemCenter' 'SC remote exec' 'FAIL' $_.Exception.Message
            }

            # Cleanup
            Remove-Item "\\$TargetServer\c$\Windows\Temp\SCA_Deploy" -Recurse -Force -ErrorAction SilentlyContinue
        }
        Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Add-Result '5. SystemCenter' 'SC reinstall' 'INFO' 'Skipped by user'
}

#============================================================
# SECTION 6 — TOMCAT: REMOTE FILE OVERWRITE (no uninstall)
#============================================================
Write-Section "6. TOMCAT — Remote File Overwrite (NewVersion\ copy only)"

$tcSvc = if ($script:DiscoveredServices) {
    $script:DiscoveredServices | Where-Object { $_.Role -eq 'Tomcat' } | Select-Object -First 1
} else { $null }

if (-not $tcSvc) {
    Add-Result '6. Tomcat' 'Tomcat service'  'WARN' 'Not discovered — skipping'
} elseif (-not $NewVersionPath) {
    Add-Result '6. Tomcat' 'NewVersion path' 'WARN' 'No path provided at startup — skipping'
} elseif (-not (Test-Path $NewVersionPath)) {
    Add-Result '6. Tomcat' 'NewVersion path' 'FAIL' "Path not found: $NewVersionPath"
} else {
    Add-Result '6. Tomcat' "Tomcat service ($($tcSvc.Name))" 'PASS' "Status=$($tcSvc.Status)"
    Add-Result '6. Tomcat' 'Tomcat home dir' `
        $(if ($tcSvc.HomeDir) {'PASS'} else {'WARN'}) `
        $(if ($tcSvc.HomeDir) { $tcSvc.HomeDir } else { 'Not resolved' })

    $newFiles = @(Get-ChildItem -Path $NewVersionPath -Recurse -File -ErrorAction SilentlyContinue)
    Add-Result '6. Tomcat' 'NewVersion file count' 'INFO' "$($newFiles.Count) file(s)"

    if ($tcSvc.HomeDir) {
        $uncTomcat  = "\\$TargetServer\$($tcSvc.HomeDir -replace '^([A-Za-z]):\\','$1$\')"
        $uncTomcatOk = Test-Path $uncTomcat
        Add-Result '6. Tomcat' 'UNC path to Tomcat home' `
            $(if ($uncTomcatOk) {'PASS'} else {'FAIL'}) $uncTomcat
    }

    if (Confirm-Action "LIVE TEST: Stop Tomcat ($($tcSvc.Name)), overwrite files from $NewVersionPath, restart?") {
        $tcName = $tcSvc.Name
        $tcHome = $tcSvc.HomeDir

        # Stop Tomcat
        $stopBlock = {
            param($n)
            $s = Get-Service -Name $n -ErrorAction Stop
            if ($s.Status -eq 'Running') {
                Stop-Service -Name $n -Force -ErrorAction Stop
                $s.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
                return "PASS Stopped $n"
            }
            return "INFO $n already stopped"
        }
        try {
            $r = Invoke-Remote -Block $stopBlock -Args @($tcName)
            $p = ($r -join '').Trim() -split '\s+', 2
            Add-Result '6. Tomcat' 'Stop Tomcat' $(if ($p[0] -eq 'PASS') {'PASS'} else {'INFO'}) ($p[1])
        }
        catch { Add-Result '6. Tomcat' 'Stop Tomcat' 'FAIL' $_.Exception.Message }

        # Protect config files in NewVersion\conf — rename to .new so they don't clobber live config
        $confPath = Join-Path $NewVersionPath 'conf'
        $renamed  = @()
        if (Test-Path $confPath) {
            foreach ($f in @('web.xml','server.xml','tomcat-users.xml','tomcat-users.xsd')) {
                $fp = Join-Path $confPath $f
                if (Test-Path $fp) {
                    Rename-Item $fp "$fp.new" -ErrorAction SilentlyContinue
                    $renamed += $fp
                    Add-Result '6. Tomcat' "Protected config $f" 'INFO' 'Renamed to .new before copy'
                }
            }
        }

        # Copy files via UNC
        $uncDest = "\\$TargetServer\$($tcHome -replace '^([A-Za-z]):\\','$1$\')"
        try {
            Copy-Item -Path "$NewVersionPath\*" -Destination $uncDest -Recurse -Force
            Add-Result '6. Tomcat' 'File overwrite via UNC' 'PASS' "$NewVersionPath -> $uncDest"
        }
        catch { Add-Result '6. Tomcat' 'File overwrite via UNC' 'FAIL' $_.Exception.Message }

        # Restore renamed config filenames
        foreach ($fp in $renamed) {
            $newName = "$fp.new"
            if (Test-Path $newName) { Rename-Item $newName $fp -ErrorAction SilentlyContinue }
        }

        # Start Tomcat
        $startBlock = {
            param($n)
            Start-Service -Name $n -ErrorAction Stop
            $s = Get-Service -Name $n
            $s.WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
            return "PASS $n running (status=$($s.Status))"
        }
        try {
            $r = Invoke-Remote -Block $startBlock -Args @($tcName)
            $p = ($r -join '').Trim() -split '\s+', 2
            Add-Result '6. Tomcat' 'Start Tomcat' $(if ($p[0] -eq 'PASS') {'PASS'} else {'WARN'}) ($p[1])
        }
        catch { Add-Result '6. Tomcat' 'Start Tomcat' 'FAIL' $_.Exception.Message }

    } else {
        Add-Result '6. Tomcat' 'Tomcat file overwrite' 'INFO' 'Skipped by user'
    }
}

#============================================================
# CLEANUP
#============================================================
if ($WinRMSession) { Remove-PSSession $WinRMSession -ErrorAction SilentlyContinue }
if ($CimSession)   { Remove-CimSession $CimSession  -ErrorAction SilentlyContinue }

#============================================================
# FINAL SUMMARY
#============================================================
Write-Host ""
Write-Host ('=' * 70) -ForegroundColor Cyan
Write-Host "  DIAGNOSTIC SUMMARY  -  $TargetServer" -ForegroundColor Cyan
Write-Host ('=' * 70) -ForegroundColor Cyan
Write-Host ""

$grouped = $script:Results | Group-Object Section
foreach ($g in $grouped) {
    Write-Host "  $($g.Name)" -ForegroundColor White
    foreach ($r in $g.Group) {
        $c = switch ($r.Status) {
            'PASS' {'Green'} 'WARN' {'Yellow'} 'FAIL' {'Red'} default {'Gray'}
        }
        $pad    = ' ' * [math]::Max(0, 44 - $r.Label.Length)
        $detail = if ($r.Detail) { "  $($r.Detail)" } else { '' }
        Write-Host ("    {0}{1}[{2}]{3}" -f $r.Label, $pad, $r.Status, $detail) -ForegroundColor $c
    }
    Write-Host ""
}

$counts = $script:Results | Group-Object Status
Write-Host "  Totals:  " -ForegroundColor White -NoNewline
foreach ($c in $counts | Sort-Object Name) {
    $col = switch ($c.Name) {'PASS' {'Green'} 'WARN' {'Yellow'} 'FAIL' {'Red'} default {'Gray'}}
    Write-Host "$($c.Name)=$($c.Count)   " -ForegroundColor $col -NoNewline
}
Write-Host ""
Write-Host ""

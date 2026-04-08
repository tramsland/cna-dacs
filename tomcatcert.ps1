#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Tomcat Keystore Management Script v6
.DESCRIPTION
    Manages Java keystores used by Tomcat. Derives Tomcat base from service
    executable path. After renewal exports cert to script directory and
    provides instructions for running the companion IIS import script locally
    on the IIS server. No WinRM or stored credentials required.
.PARAMETER WhatIf
    Show what would be executed without making any changes.
#>
param([switch]$WhatIf)

# ============================================================
# CONFIGURATION
# ============================================================
$storagePath      = "C:\temp\cert-backups"
$retentionDays    = 90
$accessLogPattern = "localhost_access_log*"
$iisLinesToScan   = 500
$scriptDir        = Split-Path -Parent $MyInvocation.MyCommand.Path

# ============================================================
# SETUP
# ============================================================
if (-not (Test-Path $storagePath)) {
    New-Item -ItemType Directory -Path $storagePath | Out-Null
}
$ts      = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
$logFile = Join-Path $storagePath "keystore-mgmt-$ts.log"

# ============================================================
# LOGGING
# ============================================================
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DETAIL")][string]$Level = "INFO",
        [string]$Server = ""
    )
    $prefix = if ($Server) { "[$Server] " } else { "" }
    $entry  = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $prefix$Message"
    Add-Content -Path $logFile -Value $entry
    switch ($Level) {
        "INFO"   { Write-Host $entry -ForegroundColor Green }
        "WARN"   { Write-Host $entry -ForegroundColor Yellow }
        "ERROR"  { Write-Host $entry -ForegroundColor Red }
        "DETAIL" { Write-Host $entry -ForegroundColor Cyan }
    }
}

# ============================================================
# FIND KEYTOOL
# ============================================================
function Find-Keytool {
    # 1. JAVA_HOME env var
    if ($env:JAVA_HOME) {
        $p = Join-Path $env:JAVA_HOME "bin\keytool.exe"
        if (Test-Path $p) { return $p }
    }

    # 2. Already on PATH
    $inPath = Get-Command keytool.exe -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }

    # 3. Known customer Java location - one level deep, no recursion
    $customerJavaRoot = "E:\customers\shared\dacs\java"
    if (Test-Path $customerJavaRoot) {
        $p = Join-Path $customerJavaRoot "bin\keytool.exe"
        if (Test-Path $p) { return $p }
        foreach ($sub in Get-ChildItem $customerJavaRoot -Directory -ErrorAction SilentlyContinue) {
            $p = Join-Path $sub.FullName "bin\keytool.exe"
            if (Test-Path $p) { return $p }
        }
    }

    # 4. Manual entry
    Write-Log "keytool.exe not found automatically." -Level WARN
    $manual = Read-Host "Enter full path to keytool.exe (or leave blank to exit)"
    if ($manual -and (Test-Path $manual)) { return $manual }
    return $null
}

# ============================================================
# READ TOMCAT CONFIG FROM SERVICE + SERVER.XML
# ============================================================
function Get-TomcatKeystoreConfig {
    # 1. Find Tomcat service by name/displayname
    $svc = Get-Service | Where-Object {
        $_.DisplayName -match "tomcat" -or $_.Name -match "tomcat"
    } | Select-Object -First 1

    # 2. Fall back to service description
    if (-not $svc) {
        Write-Log "Service not found by name - searching descriptions..." -Level WARN
        $wmi = Get-WmiObject Win32_Service |
               Where-Object { $_.Description -match "Apache Tomcat" } |
               Select-Object -First 1
        if ($wmi) {
            $svc = Get-Service -Name $wmi.Name -ErrorAction SilentlyContinue
        }
    }

    # 3. Derive TomcatBase from service executable path
    $tomcatBase = $null
    $svcName    = $null
    if ($svc) {
        $svcName = $svc.Name
        $wmiSvc  = Get-WmiObject Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
        if ($wmiSvc -and $wmiSvc.PathName) {
            $exePath    = $wmiSvc.PathName.Trim('"') -replace "\s.+$", ""
            $tomcatBase = Split-Path (Split-Path $exePath)
            Write-Log "Tomcat base from service: $tomcatBase" -Level INFO
        }
    }

    # 4. Fall back to known fixed paths
    if (-not $tomcatBase -or -not (Test-Path $tomcatBase)) {
        Write-Log "Could not derive Tomcat base from service - trying known paths..." -Level WARN
        $knownBases = @(
            "E:\customers\shared\dacs\tomcat10",
            "E:\customers\shared\dacs\tomcat",
            "C:\Tomcat"
        )
        foreach ($base in $knownBases) {
            if (Test-Path (Join-Path $base "conf\server.xml")) {
                $tomcatBase = $base
                Write-Log "Tomcat base from known path: $tomcatBase" -Level INFO
                break
            }
        }
    }

    # 5. Manual entry
    if (-not $tomcatBase) {
        Write-Log "Tomcat base not found automatically." -Level WARN
        $tomcatBase = Read-Host "Enter Tomcat base path (e.g. E:\customers\shared\dacs\tomcat10)"
        if (-not (Test-Path $tomcatBase)) {
            Write-Log "Path not found: $tomcatBase" -Level ERROR
            exit 1
        }
    }

    $serverXml = Join-Path $tomcatBase "conf\server.xml"
    if (-not (Test-Path $serverXml)) {
        Write-Log "server.xml not found at $serverXml" -Level WARN
        $serverXml = Read-Host "Enter full path to server.xml"
        if (-not (Test-Path $serverXml)) {
            Write-Log "server.xml not found at: $serverXml" -Level ERROR
            exit 1
        }
    }

    Write-Log "Reading config from: $serverXml" -Level DETAIL
    [xml]$xml  = Get-Content $serverXml
    $connector = $xml.Server.Service.Connector |
                 Where-Object { $_.SSLEnabled -eq "true" -or $_.scheme -eq "https" } |
                 Select-Object -First 1

    if (-not $connector) {
        Write-Log "No HTTPS connector found in server.xml." -Level ERROR
        exit 1
    }

    $ksFile  = $connector.keystoreFile
    $ksPass  = $connector.keystorePass
    $ksType  = $connector.keystoreType
    $keyPass = $connector.keyPass

    # Support nested SSLHostConfig
    $sslHost = $connector.SSLHostConfig
    if ($sslHost) {
        $cert = $sslHost.Certificate
        if ($cert.certificateKeystoreFile)     { $ksFile  = $cert.certificateKeystoreFile }
        if ($cert.certificateKeystorePassword) { $ksPass  = $cert.certificateKeystorePassword }
        if ($cert.certificateKeystoreType)     { $ksType  = $cert.certificateKeystoreType }
        if ($cert.certificateKeyPassword)      { $keyPass = $cert.certificateKeyPassword }
    }

    # Resolve relative paths
    if ($ksFile -and -not [System.IO.Path]::IsPathRooted($ksFile)) {
        $ksFile = Join-Path $tomcatBase $ksFile
    }
    if (-not $ksType) { $ksType = "PKCS12" }

    # Detect placeholder passwords
    foreach ($passVar in @("ksPass","keyPass")) {
        $val = Get-Variable $passVar -ValueOnly
        if ($val -match "^\$\{.+\}$") {
            Write-Log "Password is a property placeholder ($val) - enter value manually." -Level WARN
            Set-Variable $passVar (Read-Host "Enter $passVar value")
        }
    }

    # Derive log dir from server.xml AccessLog valve
    $logDir = Join-Path $tomcatBase "logs"
    $valve  = $xml.Server.Service.Engine.Host.Valve |
              Where-Object { $_.className -match "AccessLog" } |
              Select-Object -First 1
    if ($valve -and $valve.directory) {
        $vDir = $valve.directory
        if (-not [System.IO.Path]::IsPathRooted($vDir)) {
            $vDir = Join-Path $tomcatBase $vDir
        }
        $logDir = $vDir
    }

    return [PSCustomObject]@{
        KeystoreFile = $ksFile
        KeystoreType = $ksType
        KeystorePass = $ksPass
        KeyPass      = $keyPass
        ServiceName  = $svcName
        TomcatBase   = $tomcatBase
        LogDir       = $logDir
    }
}

# ============================================================
# BASE KEYTOOL ARGS
# ============================================================
function Get-BaseArgs {
    param($config)
    return @(
        "-keystore",  $config.KeystoreFile,
        "-storetype", $config.KeystoreType,
        "-storepass", $config.KeystorePass
    )
}

# ============================================================
# INVOKE KEYTOOL - masks passwords in log
# ============================================================
function Invoke-Keytool {
    param($keytool, [string[]]$ktArgs)
    $safeArgs = @()
    $prev = ""
    foreach ($a in $ktArgs) {
        if ($prev -in @("-storepass","-keypass","-srcstorepass","-deststorepass")) {
            $safeArgs += "****"
        } else {
            $safeArgs += $a
        }
        $prev = $a
    }
    Write-Log "keytool $($safeArgs -join ' ')" -Level DETAIL
    if ($WhatIf) {
        Write-Host "  [WHATIF] keytool $($safeArgs -join ' ')" -ForegroundColor Magenta
        return 0
    }
    & $keytool @ktArgs 2>&1 | ForEach-Object { Write-Log $_ -Level DETAIL }
    return $LASTEXITCODE
}

# ============================================================
# GET SANs FROM CERT DETAILS
# ============================================================
function Get-CertSANs {
    param([string[]]$certDetails)
    $sanList = [System.Collections.Generic.List[string]]::new()
    $inSan   = $false
    foreach ($line in $certDetails) {
        $t = $line.Trim()
        if ($t -match "SubjectAlternativeName") { $inSan = $true; continue }
        if ($inSan) {
            if ($t.StartsWith("DNSName:"))   { $sanList.Add("dns:$(($t -split ":",2)[1].Trim())") }
            if ($t.StartsWith("IPAddress:")) { $sanList.Add("ip:$(($t -split ":",2)[1].Trim())") }
            if ($t -eq "]" -or ($t -eq "" -and $sanList.Count -gt 0)) { break }
        }
    }
    return $sanList
}

# ============================================================
# BACKUP KEYSTORE
# ============================================================
function Backup-Keystore {
    param($config)
    $dest = Join-Path $storagePath "$(Split-Path $config.KeystoreFile -Leaf).backup.$ts"
    try {
        Copy-Item -Path $config.KeystoreFile -Destination $dest -ErrorAction Stop
        Write-Log "Keystore backed up to $dest" -Level INFO
        return $dest
    } catch {
        Write-Log "FATAL: Could not back up keystore: $_" -Level ERROR
        exit 1
    }
}

# ============================================================
# EXPORT CERT TO .CER IN SCRIPT DIRECTORY
# ============================================================
function Export-TomcatCert {
    param($keytool, $config, [string]$alias)
    $cerName = "$(Split-Path $config.KeystoreFile -Leaf)-$(Get-Date -Format 'yyyyMMdd').cer"
    $cerPath = Join-Path $scriptDir $cerName
    $baseArgs = Get-BaseArgs $config
    $rc = Invoke-Keytool $keytool (@(
        "-exportcert",
        "-alias", $alias,
        "-file",  $cerPath,
        "-rfc"
    ) + $baseArgs)
    if ($rc -eq 0) {
        $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerPath)
        Write-Log "Cert exported to $cerPath" -Level INFO
        Write-Log "Thumbprint : $($x509.Thumbprint)" -Level INFO
        Write-Log "Subject    : $($x509.Subject)" -Level INFO
        Write-Log "Expires    : $($x509.NotAfter)" -Level INFO
        return $cerPath
    } else {
        Write-Log "Failed to export cert." -Level ERROR
        return $null
    }
}

# ============================================================
# DISCOVER IIS SERVER FROM ACCESS LOG
# ============================================================
function Get-IISServerFromLog {
    param([string]$logDir)
    Write-Log "Scanning access logs in $logDir for IIS server IP..." -Level INFO
    $logFiles = Get-ChildItem $logDir -Filter $accessLogPattern -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending
    if (-not $logFiles) {
        Write-Log "No access log files found in $logDir" -Level WARN
        return $null
    }
    $ipCounts  = @{}
    $linesRead = 0
    foreach ($f in $logFiles) {
        $lines = Get-Content $f.FullName -ErrorAction SilentlyContinue
        foreach ($line in ($lines | Select-Object -Last $iisLinesToScan)) {
            if ($line -match "^(\d{1,3}(\.\d{1,3}){3})") {
                $ip = $Matches[1]
                $ipCounts[$ip] = ($ipCounts[$ip] -as [int]) + 1
            }
            $linesRead++
            if ($linesRead -ge $iisLinesToScan) { break }
        }
        if ($linesRead -ge $iisLinesToScan) { break }
    }
    if ($ipCounts.Count -eq 0) {
        Write-Log "No IPs found in access logs." -Level WARN
        return $null
    }
    $topIPs = $ipCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
    Write-Host ""
    Write-Host "  Top IPs found in access logs:" -ForegroundColor Cyan
    $i = 1
    foreach ($entry in $topIPs) {
        Write-Host "  [$i] $($entry.Key)  ($($entry.Value) hits)"
        $i++
    }
    Write-Host "  [M] Enter manually"
    Write-Host "  [S] Skip"
    Write-Host ""
    $sel = Read-Host "Select IIS server (1-$([Math]::Min(5,$topIPs.Count)), M or S)"
    if ($sel -eq "S") { return $null }
    if ($sel -eq "M") { return Read-Host "Enter IIS server hostname or IP" }
    $idx = ($sel -as [int]) - 1
    if ($idx -ge 0 -and $idx -lt $topIPs.Count) { return @($topIPs)[$idx].Key }
    Write-Log "Invalid selection." -Level WARN
    return $null
}

# ============================================================
# PUSH KEYSTORE TO SAN SERVER - no credentials, uses current session
# ============================================================
function Push-KeystoreToSanServer {
    param(
        [string]$targetServer,
        [string]$localKeystorePath,
        [string]$remoteKeystorePath,
        [string]$remoteServiceName
    )
    Write-Log "Pushing keystore to $targetServer..." -Level INFO -Server $targetServer

    # Map a temp drive to the remote server using current admin session
    $driveName = "TempCertPush"
    $remoteDir = Split-Path $remoteKeystorePath
    $uncPath   = "\\$targetServer\$($remoteDir -replace ':','$')"

    try {
        # Backup remote keystore via UNC
        if (Test-Path "$uncPath\$(Split-Path $remoteKeystorePath -Leaf)") {
            $bkDest = "$uncPath\$(Split-Path $remoteKeystorePath -Leaf).backup.$ts"
            Copy-Item "$uncPath\$(Split-Path $remoteKeystorePath -Leaf)" $bkDest -Force
            Write-Log "Remote keystore backed up to $bkDest" -Level INFO -Server $targetServer
        }

        # Copy new keystore
        if ($WhatIf) {
            Write-Host "  [WHATIF] Would copy $localKeystorePath to $uncPath" -ForegroundColor Magenta
        } else {
            Copy-Item $localKeystorePath "$uncPath\$(Split-Path $remoteKeystorePath -Leaf)" -Force
            Write-Log "Keystore copied to $uncPath" -Level INFO -Server $targetServer
        }

        # Restart Tomcat service on remote server via sc.exe (no WinRM needed)
        $svcToRestart = $remoteServiceName
        if (-not $WhatIf) {
            Write-Log "Stopping $svcToRestart on $targetServer..." -Level INFO -Server $targetServer
            $stop = & sc.exe "\\$targetServer" stop $svcToRestart 2>&1
            Start-Sleep -Seconds 5
            $start = & sc.exe "\\$targetServer" start $svcToRestart 2>&1
            Write-Log "sc stop : $stop"  -Level DETAIL -Server $targetServer
            Write-Log "sc start: $start" -Level DETAIL -Server $targetServer

            # Verify service is running
            $status = & sc.exe "\\$targetServer" query $svcToRestart 2>&1
            if ($status -match "RUNNING") {
                Write-Log "Service is running." -Level INFO -Server $targetServer
            } else {
                Write-Log "Service may not have started - verify manually." -Level WARN -Server $targetServer
            }
        } else {
            Write-Host "  [WHATIF] Would restart $svcToRestart on $targetServer via sc.exe" -ForegroundColor Magenta
        }
        return $true
    } catch {
        Write-Log "Failed to push to ${targetServer}: $_" -Level ERROR -Server $targetServer
        return $false
    }
}

# ============================================================
# RESTART LOCAL TOMCAT
# ============================================================
function Invoke-TomcatRestart {
    param($config)
    if (-not $config.ServiceName) {
        Write-Log "Tomcat service name not detected - restart manually." -Level WARN
        return
    }
    $restart = (Read-Host "  Restart Tomcat service '$($config.ServiceName)' now? (y/n)").ToLower()
    if ($restart -ne "y") {
        Write-Log "Tomcat restart skipped." -Level WARN
        return
    }
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would restart service: $($config.ServiceName)" -ForegroundColor Magenta
        return
    }
    try {
        Write-Log "Restarting $($config.ServiceName)..." -Level INFO
        Restart-Service -Name $config.ServiceName -Force -ErrorAction Stop
        Write-Log "Service restarted successfully." -Level INFO
    } catch {
        Write-Log "Failed to restart service: $_" -Level ERROR
    }
}

# ============================================================
# SAN SERVER MENU
# ============================================================
function Show-SanServerMenu {
    param($config, [System.Collections.Generic.List[string]]$sanList, [string]$mode)
    $localHost = $env:COMPUTERNAME.ToLower()
    $servers   = @()
    foreach ($san in $sanList) {
        $h = ($san -replace "^dns:", "").ToLower()
        if ($h -ne $localHost -and $h -notmatch "^\d") { $servers += $h }
    }
    if ($servers.Count -eq 0) {
        Write-Log "No remote SAN servers found." -Level WARN
        return
    }
    while ($true) {
        Write-Host ""
        Write-Host "  SAN Servers:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $servers.Count; $i++) {
            Write-Host "  [$($i+1)] $($servers[$i])"
        }
        Write-Host "  [D] Done"
        Write-Host ""
        $sel = (Read-Host "Select server to $mode keystore to (or D to finish)").ToUpper()
        if ($sel -eq "D") { break }
        $idx = ($sel -as [int]) - 1
        if ($idx -lt 0 -or $idx -ge $servers.Count) {
            Write-Host "  Invalid selection." -ForegroundColor Yellow
            continue
        }
        Push-KeystoreToSanServer `
            -targetServer       $servers[$idx] `
            -localKeystorePath  $config.KeystoreFile `
            -remoteKeystorePath $config.KeystoreFile `
            -remoteServiceName  $config.ServiceName
    }
}

# ============================================================
# COPY CERT TO SAN SERVER (menu option X)
# ============================================================
function Invoke-CopyCertToSanServer {
    param($config, $keytool)
    $baseArgs = Get-BaseArgs $config
    $details  = & $keytool -list -v @baseArgs 2>&1
    $sanList  = Get-CertSANs $details
    if ($sanList.Count -eq 0) {
        Write-Log "No SANs found in current keystore cert." -Level WARN
        return
    }
    Show-SanServerMenu -config $config -sanList $sanList -mode "copy"
}

# ============================================================
# POST-RENEWAL
# ============================================================
function Invoke-PostRenewal {
    param($keytool, $config, [string]$alias)
    Write-Host ""
    Write-Host "  -- Post-Renewal Steps --" -ForegroundColor Cyan

    # 1. Export cert to script directory
    $cerPath = Export-TomcatCert $keytool $config $alias

    # 2. Identify IIS server and show instructions
    if ($cerPath) {
        $iisServer = Get-IISServerFromLog -logDir $config.LogDir
        Write-Host ""
        Write-Host "  -- IIS Import Instructions --" -ForegroundColor Cyan
        if ($iisServer) {
            Write-Host "  IIS server identified as: $iisServer" -ForegroundColor White
        }
        Write-Host "  Copy this file to the IIS server and run the companion script:" -ForegroundColor White
        Write-Host "  Cert : $cerPath" -ForegroundColor Yellow
        Write-Host "  Then : Run Import-TomcatCertToIIS.ps1 -CerPath <path>" -ForegroundColor Yellow
        Write-Host ""
        Write-Log "Cert ready for IIS import at: $cerPath" -Level INFO
        if ($iisServer) { Write-Log "IIS server identified as: $iisServer" -Level INFO }
    }

    # 3. Push to SAN servers
    $baseArgs = Get-BaseArgs $config
    $details  = & $keytool -list -v @baseArgs 2>&1
    $sanList  = Get-CertSANs $details
    if ($sanList.Count -gt 0) {
        $push = (Read-Host "  Push updated keystore to other SAN servers? (y/n)").ToLower()
        if ($push -eq "y") {
            Show-SanServerMenu -config $config -sanList $sanList -mode "push"
        }
    }

    # 4. Restart local Tomcat
    Invoke-TomcatRestart $config
}

# ============================================================
# OLD BACKUP CLEANUP
# ============================================================
function Remove-OldBackups {
    $cutoff = (Get-Date).AddDays(-$retentionDays)
    $old    = Get-ChildItem $storagePath -Filter "*.backup.*" |
              Where-Object { $_.LastWriteTime -lt $cutoff }
    if ($old) {
        $old | Remove-Item -Force
        Write-Log "Removed $($old.Count) backup(s) older than $retentionDays days." -Level INFO
    }
}

# ============================================================
# MAIN
# ============================================================
Clear-Host
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Tomcat Keystore Management Script v6$(if($WhatIf){' [WHATIF]'})" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
if ($WhatIf) { Write-Host "  WHATIF MODE - no changes will be made`n" -ForegroundColor Magenta }

Write-Log "--- Script started. Log: $logFile ---" -Level INFO

$keytool = Find-Keytool
if (-not $keytool) {
    Write-Log "keytool.exe not found. Exiting." -Level ERROR
    exit 1
}
Write-Log "keytool: $keytool" -Level INFO

$config   = Get-TomcatKeystoreConfig
$ksExists = Test-Path $config.KeystoreFile

Write-Host ""
Write-Host "  Keystore : $($config.KeystoreFile)$(if(-not $ksExists){' (not found)'})" -ForegroundColor White
Write-Host "  Type     : $($config.KeystoreType)" -ForegroundColor White
Write-Host "  Service  : $(if($config.ServiceName){$config.ServiceName}else{'(not detected)'})" -ForegroundColor White
Write-Host "  Log Dir  : $($config.LogDir)" -ForegroundColor White
Write-Host "  Log      : $logFile" -ForegroundColor White
Write-Host ""
Write-Host "  [U] Update / renew existing certificate (self-signed)"
Write-Host "  [C] Create CSR for CA signing"
Write-Host "  [I] Import CA-signed certificate"
Write-Host "  [R] Rollback keystore from backup"
Write-Host "  [X] Copy current cert to SAN server"
Write-Host ""
$choice = (Read-Host "Select option (U/C/I/R/X)").ToUpper()

# ============================================================
# U - UPDATE / RENEW
# ============================================================
if ($choice -eq "U") {
    Write-Log "User selected [Update/Renew]." -Level INFO
    $aliasName = Read-Host "Alias to update or create (e.g. tomcat)"
    if ([string]::IsNullOrWhiteSpace($aliasName)) {
        Write-Log "Alias cannot be empty." -Level ERROR; exit 1
    }
    $baseArgs        = Get-BaseArgs $config
    $existingDetails = & $keytool -list -v @baseArgs -alias $aliasName 2>&1
    $aliasExists     = $LASTEXITCODE -eq 0

    if ($aliasExists) {
        $expiryLine   = $existingDetails | Where-Object { $_ -match "until:" }
        $dNameToUse   = ($existingDetails | Where-Object { $_ -match "Owner:" }) -replace "Owner: ", ""
        $sanListToUse = Get-CertSANs $existingDetails
        Write-Host ""
        Write-Host "  Current cert details:" -ForegroundColor Cyan
        Write-Host "  Alias  : $aliasName"
        Write-Host "  DN     : $dNameToUse"
        Write-Host "  Expiry : $expiryLine"
        Write-Host "  SANs   : $($sanListToUse -join ', ')"
        Write-Host ""
        $proceed = (Read-Host "Proceed with renewal? (y/n)").ToLower()
        if ($proceed -ne "y") { Write-Log "Renewal cancelled." -Level WARN; exit 0 }
    } else {
        Write-Log "Alias '$aliasName' not found - creating new entry." -Level WARN
        $dNameToUse   = Read-Host "Distinguished Name (e.g. CN=host.domain.com, OU=IT, O=MyOrg, C=US)"
        $sanInput     = Read-Host "SANs comma-separated (e.g. dns:host1.domain.com,dns:host2.domain.com)"
        $sanListToUse = [System.Collections.Generic.List[string]]($sanInput -split ",")
    }

    $algChoice = (Read-Host "Key algorithm [R]SA or [E]C (default R)").ToUpper()
    if ($algChoice -eq "E") {
        $keyAlg     = "EC"
        $keySizeArg = @("-groupname","secp384r1")
    } else {
        $keyAlg    = "RSA"
        $sizeInput = Read-Host "Key size (2048/4096, default 2048)"
        $keySize   = if ($sizeInput -eq "4096") { 4096 } else { 2048 }
        $keySizeArg = @("-keysize",$keySize)
    }
    $validityInput = Read-Host "Validity in days (default 397)"
    $validity      = if ($validityInput -as [int]) { [int]$validityInput } else { 397 }
    $sanExt        = "san=" + ($sanListToUse -join ",")

    Write-Host ""
    Write-Host "  -- Confirm --" -ForegroundColor Cyan
    Write-Host "  Alias    : $aliasName"
    Write-Host "  Action   : $(if($aliasExists){'Delete + regenerate'}else{'Create new'})"
    Write-Host "  DN       : $dNameToUse"
    Write-Host "  SANs     : $($sanListToUse -join ', ')"
    Write-Host "  Algorithm: $keyAlg $(if($keyAlg -eq 'RSA'){$keySize}else{'secp384r1'})"
    Write-Host "  Validity : $validity days"
    Write-Host ""
    $confirm = (Read-Host "Proceed? (y/n)").ToLower()
    if ($confirm -ne "y") { Write-Log "Renewal aborted." -Level WARN; exit 0 }

    Backup-Keystore $config

    if ($aliasExists) {
        $rc = Invoke-Keytool $keytool (@("-delete","-alias",$aliasName) + $baseArgs)
        if ($rc -ne 0) { Write-Log "Failed to delete alias." -Level ERROR; exit 1 }
        Write-Log "Old alias deleted." -Level INFO
    }

    $genArgs = @(
        "-genkeypair",
        "-alias",    $aliasName,
        "-keyalg",   $keyAlg
    ) + $keySizeArg + @(
        "-validity", $validity,
        "-dname",    $dNameToUse,
        "-ext",      $sanExt,
        "-keypass",  $config.KeyPass
    ) + $baseArgs

    $rc = Invoke-Keytool $keytool $genArgs
    if ($rc -ne 0) { Write-Log "genkeypair failed." -Level ERROR; exit 1 }
    Write-Log "New cert generated successfully." -Level INFO

    $newDetails = & $keytool -list -v @baseArgs -alias $aliasName 2>&1
    Write-Log "New expiry : $($newDetails | Where-Object { $_ -match 'until:' })" -Level INFO
    Write-Log "New SANs   : $((Get-CertSANs $newDetails) -join ', ')" -Level INFO

    Remove-OldBackups
    Invoke-PostRenewal -keytool $keytool -config $config -alias $aliasName
}

# ============================================================
# C - CREATE CSR
# ============================================================
elseif ($choice -eq "C") {
    Write-Log "User selected [Create CSR]." -Level INFO
    $aliasName = Read-Host "Alias (e.g. tomcat)"
    if ([string]::IsNullOrWhiteSpace($aliasName)) {
        Write-Log "Alias cannot be empty." -Level ERROR; exit 1
    }
    $baseArgs        = Get-BaseArgs $config
    $existingDetails = & $keytool -list -v @baseArgs -alias $aliasName 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Alias '$aliasName' not found. Generate a key pair first (option U)." -Level ERROR
        exit 1
    }
    $sanListToUse = Get-CertSANs $existingDetails
    $sanExt       = "san=" + ($sanListToUse -join ",")
    $csrName      = "$aliasName-$(Get-Date -Format 'yyyyMMdd').csr"
    $csrPath      = Join-Path $scriptDir $csrName

    $rc = Invoke-Keytool $keytool (@(
        "-certreq","-alias",$aliasName,"-ext",$sanExt,"-file",$csrPath
    ) + $baseArgs)

    if ($rc -eq 0) {
        Write-Log "CSR created at $csrPath" -Level INFO
        Write-Host "  Submit this CSR to your CA. Use option [I] to import the signed cert." -ForegroundColor Cyan
    } else {
        Write-Log "CSR creation failed." -Level ERROR
    }
}

# ============================================================
# I - IMPORT CA-SIGNED CERT
# ============================================================
elseif ($choice -eq "I") {
    Write-Log "User selected [Import CA-signed cert]." -Level INFO
    $aliasName = Read-Host "Alias the signed cert should be imported under"
    $certFile  = Read-Host "Path to signed cert file (.cer/.crt)"
    $chainFile = Read-Host "Path to intermediate cert file (leave blank if none)"
    $baseArgs  = Get-BaseArgs $config
    Backup-Keystore $config

    if ($chainFile) {
        $rc = Invoke-Keytool $keytool (@(
            "-importcert","-alias","intermediate","-file",$chainFile,"-noprompt"
        ) + $baseArgs)
        if ($rc -ne 0) { Write-Log "Intermediate cert import failed." -Level WARN }
        else { Write-Log "Intermediate cert imported." -Level INFO }
    }

    $rc = Invoke-Keytool $keytool (@(
        "-importcert","-alias",$aliasName,"-file",$certFile
    ) + $baseArgs)
    if ($rc -ne 0) { Write-Log "Signed cert import failed." -Level ERROR; exit 1 }
    Write-Log "Signed cert imported successfully." -Level INFO

    $newDetails = & $keytool -list -v @baseArgs -alias $aliasName 2>&1
    Write-Log "Expiry : $($newDetails | Where-Object { $_ -match 'until:' })" -Level INFO
    Write-Log "SANs   : $((Get-CertSANs $newDetails) -join ', ')" -Level INFO

    Invoke-PostRenewal -keytool $keytool -config $config -alias $aliasName
}

# ============================================================
# R - ROLLBACK
# ============================================================
elseif ($choice -eq "R") {
    Write-Log "User selected [Rollback]." -Level INFO
    $backups = Get-ChildItem $storagePath -Filter "*.backup.*" |
               Sort-Object LastWriteTime -Descending
    if (-not $backups) {
        Write-Log "No backups found in $storagePath" -Level WARN; exit 0
    }
    Write-Host ""
    Write-Host "  Available backups:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $backups.Count; $i++) {
        Write-Host "  [$($i+1)] $($backups[$i].Name)  ($($backups[$i].LastWriteTime))"
    }
    $sel = (Read-Host "Select backup to restore (number)") -as [int]
    if ($sel -lt 1 -or $sel -gt $backups.Count) {
        Write-Log "Invalid selection." -Level ERROR; exit 1
    }
    $src = $backups[$sel-1].FullName
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would restore $src to $($config.KeystoreFile)" -ForegroundColor Magenta
    } else {
        Copy-Item $src $config.KeystoreFile -Force
        Write-Log "Restored $src to $($config.KeystoreFile)" -Level INFO
        Invoke-TomcatRestart $config
    }
}

# ============================================================
# X - COPY CERT TO SAN SERVER
# ============================================================
elseif ($choice -eq "X") {
    Write-Log "User selected [Copy cert to SAN server]." -Level INFO
    Invoke-CopyCertToSanServer -config $config -keytool $keytool
}

else {
    Write-Log "Invalid option selected." -Level ERROR
}

Write-Log "--- Script complete ---" -Level INFO

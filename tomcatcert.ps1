#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Tomcat Keystore Management Script v7
.DESCRIPTION
    Manages Java keystores used by Tomcat. Derives Tomcat base from service
    executable path. After renewal exports cert to script directory and
    imports to IIS Trusted Root via scheduled task. Pushes keystore to SAN
    servers via UNC and restarts remote Tomcat via sc.exe.
    No WinRM or stored credentials required - run from admin console.
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
$svcStopTimeout   = 60   # seconds to wait for service to stop
$svcStartTimeout  = 60   # seconds to wait for service to start
$certWarnDays     = 30   # warn if cert expires within this many days
$scriptDir        = Split-Path -Parent $MyInvocation.MyCommand.Path

# ============================================================
# SETUP
# ============================================================
if (-not (Test-Path $storagePath)) {
    New-Item -ItemType Directory -Path $storagePath | Out-Null
}
$ts      = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
$logFile = Join-Path $storagePath "keystore-mgmt-$ts.log"

# Create log file and restrict ACL before first write
New-Item -Path $logFile -ItemType File -Force | Out-Null
try {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Administrators","FullControl","Allow"
    )))
    Set-Acl -Path $logFile -AclObject $acl -ErrorAction Stop
} catch {
    Write-Host "[WARN] Could not restrict log file ACL: $_" -ForegroundColor Yellow
}

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
# RUN SUMMARY - tracks outcomes across all post-renewal steps
# ============================================================
$runSummary = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Summary {
    param([string]$Step, [string]$Target, [string]$Status, [string]$Note = "")
    $script:runSummary.Add([PSCustomObject]@{
        Step   = $Step
        Target = $Target
        Status = $Status
        Note   = $Note
    })
}

function Show-Summary {
    Write-Host ""
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host "  POST-RENEWAL SUMMARY" -ForegroundColor Cyan
    Write-Host "  ================================================" -ForegroundColor Cyan
    foreach ($row in $script:runSummary) {
        $color = switch ($row.Status) {
            "OK"      { "Green" }
            "WARN"    { "Yellow" }
            "FAILED"  { "Red" }
            "SKIPPED" { "Gray" }
            default   { "White" }
        }
        $line = "  [{0}] {1,-22} {2,-10} {3}" -f $row.Status, $row.Step, $row.Target, $row.Note
        Write-Host $line -ForegroundColor $color
    }
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host ""

    # Flag any items needing manual action
    $manual = $script:runSummary | Where-Object { $_.Status -in @("FAILED","WARN") }
    if ($manual) {
        Write-Host "  Items requiring manual attention:" -ForegroundColor Yellow
        foreach ($m in $manual) {
            Write-Host "  - $($m.Step) on $($m.Target): $($m.Note)" -ForegroundColor Yellow
        }
        Write-Host ""
    }
}

# ============================================================
# FIND KEYTOOL
# ============================================================
function Find-Keytool {
    if ($env:JAVA_HOME) {
        $p = Join-Path $env:JAVA_HOME "bin\keytool.exe"
        if (Test-Path $p) { return $p }
    }
    $inPath = Get-Command keytool.exe -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }

    $customerJavaRoot = "E:\customers\shared\dacs\java"
    if (Test-Path $customerJavaRoot) {
        $p = Join-Path $customerJavaRoot "bin\keytool.exe"
        if (Test-Path $p) { return $p }
        foreach ($sub in Get-ChildItem $customerJavaRoot -Directory -ErrorAction SilentlyContinue) {
            $p = Join-Path $sub.FullName "bin\keytool.exe"
            if (Test-Path $p) { return $p }
        }
    }

    Write-Log "keytool.exe not found automatically." -Level WARN
    $manual = Read-Host "Enter full path to keytool.exe (or leave blank to exit)"
    if ($manual -and (Test-Path $manual)) { return $manual }
    return $null
}

# ============================================================
# READ TOMCAT CONFIG FROM SERVICE + SERVER.XML
# ============================================================
function Get-TomcatKeystoreConfig {
    $svc = Get-Service | Where-Object {
        $_.DisplayName -match "tomcat" -or $_.Name -match "tomcat"
    } | Select-Object -First 1

    if (-not $svc) {
        Write-Log "Service not found by name - searching descriptions..." -Level WARN
        $wmi = Get-WmiObject Win32_Service |
               Where-Object { $_.Description -match "Apache Tomcat" } |
               Select-Object -First 1
        if ($wmi) {
            $svc = Get-Service -Name $wmi.Name -ErrorAction SilentlyContinue
        }
    }

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

    if (-not $tomcatBase -or -not (Test-Path $tomcatBase)) {
        Write-Log "Could not derive Tomcat base from service - trying known paths..." -Level WARN
        foreach ($base in @("E:\customers\shared\dacs\tomcat10","E:\customers\shared\dacs\tomcat","C:\Tomcat")) {
            if (Test-Path (Join-Path $base "conf\server.xml")) {
                $tomcatBase = $base
                Write-Log "Tomcat base from known path: $tomcatBase" -Level INFO
                break
            }
        }
    }

    if (-not $tomcatBase) {
        Write-Log "Tomcat base not found automatically." -Level WARN
        $tomcatBase = Read-Host "Enter Tomcat base path (e.g. E:\customers\shared\dacs\tomcat10)"
        if (-not (Test-Path $tomcatBase)) {
            Write-Log "Path not found: $tomcatBase" -Level ERROR; exit 1
        }
    }

    $serverXml = Join-Path $tomcatBase "conf\server.xml"
    if (-not (Test-Path $serverXml)) {
        Write-Log "server.xml not found at $serverXml" -Level WARN
        $serverXml = Read-Host "Enter full path to server.xml"
        if (-not (Test-Path $serverXml)) {
            Write-Log "server.xml not found at: $serverXml" -Level ERROR; exit 1
        }
    }

    Write-Log "Reading config from: $serverXml" -Level DETAIL
    [xml]$xml  = Get-Content $serverXml
    $connector = $xml.Server.Service.Connector |
                 Where-Object { $_.SSLEnabled -eq "true" -or $_.scheme -eq "https" } |
                 Select-Object -First 1
    if (-not $connector) {
        Write-Log "No HTTPS connector found in server.xml." -Level ERROR; exit 1
    }

    $ksFile  = $connector.keystoreFile
    $ksPass  = $connector.keystorePass
    $ksType  = $connector.keystoreType
    $keyPass = $connector.keyPass
    $keyAlias = $connector.keyAlias

    $sslHost = $connector.SSLHostConfig
    if ($sslHost) {
        $cert = $sslHost.Certificate
        if ($cert.certificateKeystoreFile)     { $ksFile   = $cert.certificateKeystoreFile }
        if ($cert.certificateKeystorePassword) { $ksPass   = $cert.certificateKeystorePassword }
        if ($cert.certificateKeystoreType)     { $ksType   = $cert.certificateKeystoreType }
        if ($cert.certificateKeyPassword)      { $keyPass  = $cert.certificateKeyPassword }
        if ($cert.certificateKeyAlias)         { $keyAlias = $cert.certificateKeyAlias }
    }

    if ($ksFile -and -not [System.IO.Path]::IsPathRooted($ksFile)) {
        $ksFile = Join-Path $tomcatBase $ksFile
    }
    if (-not $ksType) { $ksType = "PKCS12" }

    foreach ($passVar in @("ksPass","keyPass")) {
        $val = Get-Variable $passVar -ValueOnly
        if ($val -match "^\$\{.+\}$") {
            Write-Log "Password is a property placeholder ($val) - enter value manually." -Level WARN
            Set-Variable $passVar (Read-Host "Enter $passVar value")
        }
    }

    $logDir = Join-Path $tomcatBase "logs"
    $valve  = $xml.Server.Service.Engine.Host.Valve |
              Where-Object { $_.className -match "AccessLog" } |
              Select-Object -First 1
    if ($valve -and $valve.directory) {
        $vDir = $valve.directory
        if (-not [System.IO.Path]::IsPathRooted($vDir)) { $vDir = Join-Path $tomcatBase $vDir }
        $logDir = $vDir
    }

    return [PSCustomObject]@{
        KeystoreFile = $ksFile
        KeystoreType = $ksType
        KeystorePass = $ksPass
        KeyPass      = $keyPass
        KeyAlias     = $keyAlias
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
    $safeArgs = @(); $prev = ""
    foreach ($a in $ktArgs) {
        $safeArgs += if ($prev -in @("-storepass","-keypass","-srcstorepass","-deststorepass")) { "****" } else { $a }
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
# VALIDATE KEYSTORE PASSWORD
# ============================================================
function Test-KeystorePassword {
    param($keytool, $config)
    Write-Log "Validating keystore password..." -Level INFO
    $baseArgs = Get-BaseArgs $config
    & $keytool -list @baseArgs 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Keystore password validation failed - check KeystorePass in server.xml." -Level ERROR
        return $false
    }
    Write-Log "Keystore password validated." -Level INFO
    return $true
}

# ============================================================
# CHECK CERT EXPIRY
# ============================================================
function Show-CertExpiry {
    param($keytool, $config)
    $baseArgs = Get-BaseArgs $config
    $details  = & $keytool -list -v @baseArgs 2>&1
    $entries  = $details | Where-Object { $_ -match "Alias name:" }
    if (-not $entries) { return }

    Write-Host ""
    Write-Host "  Current keystore entries:" -ForegroundColor Cyan
    $currentAlias = $null
    foreach ($line in $details) {
        if ($line -match "Alias name:\s*(.+)") {
            $currentAlias = $Matches[1].Trim()
        }
        if ($line -match "Valid from:.+until:\s*(.+)") {
            $expiryStr = $Matches[1].Trim()
            try {
                $expiry  = [datetime]::Parse($expiryStr)
                $daysLeft = ($expiry - (Get-Date)).Days
                $color   = if ($daysLeft -lt 0) { "Red" }
                           elseif ($daysLeft -le $certWarnDays) { "Yellow" }
                           else { "Green" }
                Write-Host ("  {0,-30} Expires: {1:yyyy-MM-dd}  ({2} days)" -f $currentAlias, $expiry, $daysLeft) -ForegroundColor $color
                if ($daysLeft -lt 0) {
                    Write-Log "EXPIRED: Alias '$currentAlias' expired $([Math]::Abs($daysLeft)) days ago." -Level ERROR
                } elseif ($daysLeft -le $certWarnDays) {
                    Write-Log "WARNING: Alias '$currentAlias' expires in $daysLeft days." -Level WARN
                }
            } catch {
                Write-Host "  $currentAlias  - could not parse expiry" -ForegroundColor Gray
            }
        }
    }
    Write-Host ""
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
            if ($t.StartsWith("DNSName:"))   { $sanList.Add("dns:$(($t -split ':',2)[1].Trim())") }
            if ($t.StartsWith("IPAddress:")) { $sanList.Add("ip:$(($t -split ':',2)[1].Trim())") }
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
    $cerName  = "$(Split-Path $config.KeystoreFile -Leaf)-$(Get-Date -Format 'yyyyMMdd').cer"
    $cerPath  = Join-Path $scriptDir $cerName
    $baseArgs = Get-BaseArgs $config
    $rc = Invoke-Keytool $keytool (@(
        "-exportcert", "-alias", $alias, "-file", $cerPath, "-rfc"
    ) + $baseArgs)
    if ($rc -eq 0) {
        $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerPath)
        Write-Log "Cert exported to $cerPath" -Level INFO
        Write-Log "Thumbprint : $($x509.Thumbprint)" -Level INFO
        Write-Log "Subject    : $($x509.Subject)" -Level INFO
        Write-Log "Expires    : $($x509.NotAfter)" -Level INFO
        return $cerPath
    }
    Write-Log "Failed to export cert." -Level ERROR
    return $null
}

# ============================================================
# CLEAN UP OLD .CER AND .CSR FILES IN SCRIPT DIRECTORY
# ============================================================
function Remove-OldCertFiles {
    $cutoff = (Get-Date).AddDays(-$retentionDays)
    foreach ($ext in @("*.cer","*.csr")) {
        $old = Get-ChildItem $scriptDir -Filter $ext -ErrorAction SilentlyContinue |
               Where-Object { $_.LastWriteTime -lt $cutoff }
        if ($old) {
            $old | Remove-Item -Force
            Write-Log "Removed $($old.Count) old $ext file(s) from script directory." -Level INFO
        }
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

    # Count IP hits per log file then find IPs consistent across multiple files
    $ipPerFile = @{}
    $filesRead = 0
    foreach ($f in $logFiles | Select-Object -First 5) {
        $lines = Get-Content $f.FullName -ErrorAction SilentlyContinue |
                 Select-Object -Last $iisLinesToScan
        $seen  = @{}
        foreach ($line in $lines) {
            if ($line -match "^(\d{1,3}(\.\d{1,3}){3})") {
                $ip = $Matches[1]
                if (-not $seen[$ip]) {
                    $ipPerFile[$ip] = ($ipPerFile[$ip] -as [int]) + 1
                    $seen[$ip] = $true
                }
            }
        }
        $filesRead++
    }

    if ($ipPerFile.Count -eq 0) {
        Write-Log "No IPs found in access logs." -Level WARN
        return $null
    }

    # Sort by consistency (appears in most log files) then frequency
    $topIPs = $ipPerFile.GetEnumerator() |
              Sort-Object Value -Descending |
              Select-Object -First 5

    Write-Host ""
    Write-Host "  IPs found consistently across log files:" -ForegroundColor Cyan
    $i = 1
    foreach ($entry in $topIPs) {
        Write-Host "  [$i] $($entry.Key)  (seen in $($entry.Value) of $filesRead log files)"
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
# IMPORT CERT TO IIS TRUSTED ROOT - admin console, no WinRM
# ============================================================
function Import-CertToIIS {
    param([string]$iisServer, [string]$cerPath)
    Write-Log "Importing cert to IIS Trusted Root on $iisServer..." -Level INFO

    # Verify admin share reachable
    if (-not (Test-Path "\\$iisServer\C$")) {
        Write-Log "Cannot reach \\$iisServer\C$ - check admin share access." -Level ERROR
        Add-Summary "IIS Cert Import" $iisServer "FAILED" "Admin share unreachable"
        return $false
    }

    $remoteTemp    = "\\$iisServer\C$\Windows\Temp"
    $remoteCer     = "$remoteTemp\$(Split-Path $cerPath -Leaf)"
    $remoteCerLocal = "C:\Windows\Temp\$(Split-Path $cerPath -Leaf)"
    $taskName      = "TomcatCertImport_$ts"

    if ($WhatIf) {
        Write-Host "  [WHATIF] Would copy $cerPath to $remoteCer" -ForegroundColor Magenta
        Write-Host "  [WHATIF] Would run certutil -addstore Root on $iisServer" -ForegroundColor Magenta
        Add-Summary "IIS Cert Import" $iisServer "OK" "WhatIf"
        return $true
    }

    try {
        Copy-Item $cerPath $remoteCer -Force -ErrorAction Stop
        Write-Log "Cert copied to $remoteCer" -Level INFO
    } catch {
        Write-Log "Failed to copy cert to $remoteTemp : $_" -Level ERROR
        Add-Summary "IIS Cert Import" $iisServer "FAILED" "Copy failed: $_"
        return $false
    }

    $cmd = "certutil -addstore -f Root `"$remoteCerLocal`""
    & schtasks.exe /create /s $iisServer /tn $taskName /ru "SYSTEM" `
        /sc ONCE /st 00:00 /tr "cmd.exe /c $cmd" /f 2>&1 |
        ForEach-Object { Write-Log $_ -Level DETAIL }
    & schtasks.exe /run /s $iisServer /tn $taskName 2>&1 |
        ForEach-Object { Write-Log $_ -Level DETAIL }
    Start-Sleep -Seconds 5
    & schtasks.exe /delete /s $iisServer /tn $taskName /f 2>&1 |
        ForEach-Object { Write-Log $_ -Level DETAIL }
    Remove-Item $remoteCer -Force -ErrorAction SilentlyContinue

    Write-Log "Cert import task completed on $iisServer - verify in certlm.msc" -Level INFO
    Add-Summary "IIS Cert Import" $iisServer "OK" "Verify in certlm.msc"
    return $true
}

# ============================================================
# WAIT FOR SERVICE STATE
# ============================================================
function Wait-ServiceState {
    param([string]$server, [string]$svcName, [string]$desiredState, [int]$timeoutSec)
    $elapsed = 0
    while ($elapsed -lt $timeoutSec) {
        $query = & sc.exe "\\$server" query $svcName 2>&1
        if ($query -match $desiredState) { return $true }
        Start-Sleep -Seconds 3
        $elapsed += 3
    }
    return $false
}

# ============================================================
# FIND TOMCAT SERVICE + KEYSTORE PATH ON REMOTE SERVER
# ============================================================
function Get-RemoteTomcatInfo {
    param([string]$targetServer, [string]$localKeystoreLeaf)

    # Check server is reachable first
    if (-not (Test-Path "\\$targetServer\C$")) {
        Write-Log "Cannot reach \\$targetServer\C$ - server may be offline or admin share blocked." -Level ERROR -Server $targetServer
        return $null
    }

    # WMI query with timeout handling
    $wmiSvc = $null
    try {
        $job = Start-Job {
            param($s)
            Get-WmiObject Win32_Service -ComputerName $s -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "tomcat" -or $_.DisplayName -match "tomcat" } |
            Select-Object -First 1
        } -ArgumentList $targetServer
        $done = Wait-Job $job -Timeout $wmiTimeout
        if ($done) {
            $wmiSvc = Receive-Job $job
        } else {
            Write-Log "WMI query timed out on $targetServer" -Level WARN -Server $targetServer
        }
        Remove-Job $job -Force
    } catch {
        Write-Log "WMI query failed on ${targetServer}: $_" -Level WARN -Server $targetServer
    }

    # Fall back to description search
    if (-not $wmiSvc) {
        try {
            $job = Start-Job {
                param($s)
                Get-WmiObject Win32_Service -ComputerName $s -ErrorAction SilentlyContinue |
                Where-Object { $_.Description -match "Apache Tomcat" } |
                Select-Object -First 1
            } -ArgumentList $targetServer
            $done = Wait-Job $job -Timeout $wmiTimeout
            if ($done) { $wmiSvc = Receive-Job $job }
            Remove-Job $job -Force
        } catch {
            Write-Log "WMI description search failed on ${targetServer}: $_" -Level WARN -Server $targetServer
        }
    }

    $svcName    = $null
    $tomcatBase = $null
    $ksPath     = $null

    if ($wmiSvc) {
        $svcName    = $wmiSvc.Name
        $exePath    = $wmiSvc.PathName.Trim('"') -replace "\s.+$", ""
        $tomcatBase = Split-Path (Split-Path $exePath)
        Write-Log "Service: $svcName  Base: $tomcatBase" -Level INFO -Server $targetServer

        $uncConf = "\\$targetServer\$($tomcatBase -replace ':','$')\conf\server.xml"
        if (Test-Path $uncConf) {
            [xml]$xml  = Get-Content $uncConf -ErrorAction SilentlyContinue
            $conn      = $xml.Server.Service.Connector |
                         Where-Object { $_.SSLEnabled -eq "true" -or $_.scheme -eq "https" } |
                         Select-Object -First 1
            if ($conn) {
                $ksFile = $conn.keystoreFile
                if ($conn.SSLHostConfig -and $conn.SSLHostConfig.Certificate.certificateKeystoreFile) {
                    $ksFile = $conn.SSLHostConfig.Certificate.certificateKeystoreFile
                }
                if ($ksFile) {
                    if (-not [System.IO.Path]::IsPathRooted($ksFile)) {
                        $ksFile = Join-Path $tomcatBase $ksFile
                    }
                    $ksPath = $ksFile
                    Write-Log "Keystore from server.xml: $ksPath" -Level INFO -Server $targetServer
                }
            }
        }
    }

    # Fall back to known paths
    if (-not $ksPath) {
        Write-Log "Trying known Tomcat paths..." -Level WARN -Server $targetServer
        foreach ($base in @("E:\customers\shared\dacs\tomcat10","E:\customers\shared\dacs\tomcat")) {
            $uncBase = "\\$targetServer\$($base -replace ':','$')"
            if (Test-Path $uncBase) {
                $tomcatBase = $base
                $uncConf    = "$uncBase\conf\server.xml"
                if (Test-Path $uncConf) {
                    [xml]$xml = Get-Content $uncConf -ErrorAction SilentlyContinue
                    $conn     = $xml.Server.Service.Connector |
                                Where-Object { $_.SSLEnabled -eq "true" -or $_.scheme -eq "https" } |
                                Select-Object -First 1
                    if ($conn) {
                        $ksFile = $conn.keystoreFile
                        if ($conn.SSLHostConfig -and $conn.SSLHostConfig.Certificate.certificateKeystoreFile) {
                            $ksFile = $conn.SSLHostConfig.Certificate.certificateKeystoreFile
                        }
                        if ($ksFile) {
                            if (-not [System.IO.Path]::IsPathRooted($ksFile)) {
                                $ksFile = Join-Path $tomcatBase $ksFile
                            }
                            $ksPath = $ksFile
                        }
                    }
                }
                if (-not $ksPath) {
                    $ksPath = Join-Path $tomcatBase "conf\$localKeystoreLeaf"
                }
                Write-Log "Using known path: $tomcatBase  Keystore: $ksPath" -Level INFO -Server $targetServer
                break
            }
        }
    }

    if (-not $ksPath) { return $null }

    return [PSCustomObject]@{
        ServiceName  = $svcName
        TomcatBase   = $tomcatBase
        KeystorePath = $ksPath
    }
}

# ============================================================
# PUSH KEYSTORE TO SAN SERVER
# ============================================================
function Push-KeystoreToSanServer {
    param([string]$targetServer, [string]$localKeystorePath)
    Write-Log "Starting push to $targetServer..." -Level INFO -Server $targetServer

    $remoteInfo = Get-RemoteTomcatInfo -targetServer $targetServer `
                  -localKeystoreLeaf (Split-Path $localKeystorePath -Leaf)

    if (-not $remoteInfo) {
        Write-Log "Could not determine remote config - skipping $targetServer." -Level ERROR -Server $targetServer
        Add-Summary "Keystore Push" $targetServer "FAILED" "Could not determine remote config"
        return $false
    }

    $ksLeaf    = Split-Path $remoteInfo.KeystorePath -Leaf
    $remoteDir = Split-Path $remoteInfo.KeystorePath
    $uncDir    = "\\$targetServer\$($remoteDir -replace ':','$')"
    $uncKs     = "$uncDir\$ksLeaf"

    Write-Log "Remote keystore: $($remoteInfo.KeystorePath)" -Level INFO -Server $targetServer
    Write-Log "Service        : $($remoteInfo.ServiceName)" -Level INFO -Server $targetServer

    try {
        # Backup
        if (Test-Path $uncKs) {
            $bkDest = "$uncKs.backup.$ts"
            if ($WhatIf) {
                Write-Host "  [WHATIF] Would backup $uncKs to $bkDest" -ForegroundColor Magenta
            } else {
                Copy-Item $uncKs $bkDest -Force
                Write-Log "Remote keystore backed up to $bkDest" -Level INFO -Server $targetServer
            }
        }

        # Copy
        if ($WhatIf) {
            Write-Host "  [WHATIF] Would copy $localKeystorePath to $uncKs" -ForegroundColor Magenta
        } else {
            Copy-Item $localKeystorePath $uncKs -Force -ErrorAction Stop
            Write-Log "Keystore copied to $uncKs" -Level INFO -Server $targetServer
        }

        # Restart service - sc.exe needs short hostname not FQDN
        if ($remoteInfo.ServiceName) {
            $shortName = $targetServer -replace '\..*', ''
            if ($WhatIf) {
                Write-Host "  [WHATIF] Would restart $($remoteInfo.ServiceName) on $shortName" -ForegroundColor Magenta
            } else {
                Write-Log "Stopping $($remoteInfo.ServiceName)..." -Level INFO -Server $targetServer
                & sc.exe "\\$shortName" stop $remoteInfo.ServiceName 2>&1 |
                    ForEach-Object { Write-Log $_ -Level DETAIL -Server $targetServer }

                $stopped = Wait-ServiceState $shortName $remoteInfo.ServiceName "STOPPED" $svcStopTimeout
                if (-not $stopped) {
                    Write-Log "Service did not stop within $svcStopTimeout seconds." -Level WARN -Server $targetServer
                }

                & sc.exe "\\$shortName" start $remoteInfo.ServiceName 2>&1 |
                    ForEach-Object { Write-Log $_ -Level DETAIL -Server $targetServer }

                $started = Wait-ServiceState $shortName $remoteInfo.ServiceName "RUNNING" $svcStartTimeout
                if ($started) {
                    Write-Log "Service is running." -Level INFO -Server $targetServer
                    Add-Summary "Keystore Push" $targetServer "OK" "Service restarted"
                } else {
                    Write-Log "Service did not start within $svcStartTimeout seconds - verify manually." -Level WARN -Server $targetServer
                    Add-Summary "Keystore Push" $targetServer "WARN" "Service may not have started"
                }
            }
        } else {
            Write-Log "No service found - restart Tomcat manually on $targetServer." -Level WARN -Server $targetServer
            Add-Summary "Keystore Push" $targetServer "WARN" "Keystore copied - restart Tomcat manually"
        }
        return $true
    } catch {
        Write-Log "Push failed for ${targetServer}: $_" -Level ERROR -Server $targetServer
        Add-Summary "Keystore Push" $targetServer "FAILED" "$_"
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
        Add-Summary "Local Restart" $env:COMPUTERNAME "WARN" "Service name not detected"
        return
    }
    $restart = (Read-Host "  Restart Tomcat service '$($config.ServiceName)' now? (y/n)").ToLower()
    if ($restart -ne "y") {
        Write-Log "Tomcat restart skipped." -Level WARN
        Add-Summary "Local Restart" $env:COMPUTERNAME "SKIPPED" "User skipped restart"
        return
    }
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would restart service: $($config.ServiceName)" -ForegroundColor Magenta
        Add-Summary "Local Restart" $env:COMPUTERNAME "OK" "WhatIf"
        return
    }
    try {
        Write-Log "Stopping $($config.ServiceName)..." -Level INFO
        Stop-Service -Name $config.ServiceName -Force -ErrorAction Stop
        $stopped = Wait-ServiceState $env:COMPUTERNAME $config.ServiceName "STOPPED" $svcStopTimeout
        if (-not $stopped) {
            Write-Log "Service did not stop within $svcStopTimeout seconds." -Level WARN
        }
        Start-Service -Name $config.ServiceName -ErrorAction Stop
        $started = Wait-ServiceState $env:COMPUTERNAME $config.ServiceName "RUNNING" $svcStartTimeout
        if ($started) {
            Write-Log "Service is running." -Level INFO
            Add-Summary "Local Restart" $env:COMPUTERNAME "OK" ""
        } else {
            Write-Log "Service did not start within $svcStartTimeout seconds - verify manually." -Level WARN
            Add-Summary "Local Restart" $env:COMPUTERNAME "WARN" "Did not start within timeout"
        }
    } catch {
        Write-Log "Failed to restart service: $_" -Level ERROR
        Add-Summary "Local Restart" $env:COMPUTERNAME "FAILED" "$_"
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
        if ($h -ne $localHost) { $servers += $h }
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
            -targetServer      $servers[$idx] `
            -localKeystorePath $config.KeystoreFile
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

    # 1. Export cert
    $cerPath = Export-TomcatCert $keytool $config $alias
    if ($cerPath) {
        Add-Summary "Cert Export" $env:COMPUTERNAME "OK" $cerPath
    } else {
        Add-Summary "Cert Export" $env:COMPUTERNAME "FAILED" ""
    }

    # 2. IIS import
    if ($cerPath) {
        $iisServer = Get-IISServerFromLog -logDir $config.LogDir
        if ($iisServer) {
            Import-CertToIIS -iisServer $iisServer -cerPath $cerPath
        } else {
            Write-Log "IIS server not identified - import cert manually from: $cerPath" -Level WARN
            Add-Summary "IIS Cert Import" "(manual)" "SKIPPED" "Copy $cerPath to IIS server"
        }
    }

    # 3. Push to SAN servers
    $baseArgs = Get-BaseArgs $config
    $details  = & $keytool -list -v @baseArgs 2>&1
    $sanList  = Get-CertSANs $details
    if ($sanList.Count -gt 0) {
        $push = (Read-Host "  Push updated keystore to other SAN servers? (y/n)").ToLower()
        if ($push -eq "y") {
            Show-SanServerMenu -config $config -sanList $sanList -mode "push"
        } else {
            Add-Summary "SAN Push" "(skipped)" "SKIPPED" "User skipped"
        }
    }

    # 4. Restart local Tomcat
    Invoke-TomcatRestart $config

    # 5. Clean up old cert files
    Remove-OldCertFiles

    # 6. Show summary
    Show-Summary
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
Write-Host "  Tomcat Keystore Management Script v7$(if($WhatIf){' [WHATIF]'})" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
if ($WhatIf) { Write-Host "  WHATIF MODE - no changes will be made`n" -ForegroundColor Magenta }

Write-Log "--- Script started. Log: $logFile ---" -Level INFO

$keytool = Find-Keytool
if (-not $keytool) {
    Write-Log "keytool.exe not found. Exiting." -Level ERROR; exit 1
}
Write-Log "keytool: $keytool" -Level INFO

$config   = Get-TomcatKeystoreConfig
$ksExists = Test-Path $config.KeystoreFile

Write-Host ""
Write-Host "  Keystore : $($config.KeystoreFile)$(if(-not $ksExists){' (not found)'})" -ForegroundColor White
Write-Host "  Type     : $($config.KeystoreType)" -ForegroundColor White
Write-Host "  Service  : $(if($config.ServiceName){$config.ServiceName}else{'(not detected)'})" -ForegroundColor White
Write-Host "  Alias    : $(if($config.KeyAlias){$config.KeyAlias}else{'(not set in server.xml)'})" -ForegroundColor White
Write-Host "  Log Dir  : $($config.LogDir)" -ForegroundColor White
Write-Host "  Log      : $logFile" -ForegroundColor White

# Validate password and show cert expiry before menu
if ($ksExists) {
    if (-not (Test-KeystorePassword $keytool $config)) { exit 1 }
    Show-CertExpiry $keytool $config
}

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

    # Warn if alias does not match server.xml keyAlias
    if ($config.KeyAlias -and $aliasName -ne $config.KeyAlias) {
        Write-Host ""
        Write-Host "  WARNING: Entered alias '$aliasName' does not match keyAlias '$($config.KeyAlias)' in server.xml." -ForegroundColor Yellow
        Write-Host "  Tomcat will use '$($config.KeyAlias)' - the new cert may not be loaded." -ForegroundColor Yellow
        $cont = (Read-Host "  Continue anyway? (y/n)").ToLower()
        if ($cont -ne "y") { exit 0 }
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

    $genArgs = @("-genkeypair","-alias",$aliasName,"-keyalg",$keyAlg) +
               $keySizeArg +
               @("-validity",$validity,"-dname",$dNameToUse,"-ext",$sanExt,"-keypass",$config.KeyPass) +
               $baseArgs

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
        Write-Log "Alias '$aliasName' not found. Generate a key pair first (option U)." -Level ERROR; exit 1
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
        Show-Summary
    }
}

# ============================================================
# X - COPY CERT TO SAN SERVER
# ============================================================
elseif ($choice -eq "X") {
    Write-Log "User selected [Copy cert to SAN server]." -Level INFO
    Invoke-CopyCertToSanServer -config $config -keytool $keytool
    Show-Summary
}

else {
    Write-Log "Invalid option selected." -Level ERROR
}

Write-Log "--- Script complete ---" -Level INFO#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Tomcat Keystore Management Script v7
.DESCRIPTION
    Manages Java keystores used by Tomcat. Derives Tomcat base from service
    executable path. After renewal exports cert to script directory and
    imports to IIS Trusted Root via scheduled task. Pushes keystore to SAN
    servers via UNC and restarts remote Tomcat via sc.exe.
    No WinRM or stored credentials required - run from admin console.
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
$svcStopTimeout   = 60   # seconds to wait for service to stop
$svcStartTimeout  = 60   # seconds to wait for service to start
$certWarnDays     = 30   # warn if cert expires within this many days
$scriptDir        = Split-Path -Parent $MyInvocation.MyCommand.Path

# ============================================================
# SETUP
# ============================================================
if (-not (Test-Path $storagePath)) {
    New-Item -ItemType Directory -Path $storagePath | Out-Null
}
$ts      = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
$logFile = Join-Path $storagePath "keystore-mgmt-$ts.log"

# Create log file and restrict ACL before first write
New-Item -Path $logFile -ItemType File -Force | Out-Null
try {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Administrators","FullControl","Allow"
    )))
    Set-Acl -Path $logFile -AclObject $acl -ErrorAction Stop
} catch {
    Write-Host "[WARN] Could not restrict log file ACL: $_" -ForegroundColor Yellow
}

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
# RUN SUMMARY - tracks outcomes across all post-renewal steps
# ============================================================
$runSummary = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Summary {
    param([string]$Step, [string]$Target, [string]$Status, [string]$Note = "")
    $script:runSummary.Add([PSCustomObject]@{
        Step   = $Step
        Target = $Target
        Status = $Status
        Note   = $Note
    })
}

function Show-Summary {
    Write-Host ""
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host "  POST-RENEWAL SUMMARY" -ForegroundColor Cyan
    Write-Host "  ================================================" -ForegroundColor Cyan
    foreach ($row in $script:runSummary) {
        $color = switch ($row.Status) {
            "OK"      { "Green" }
            "WARN"    { "Yellow" }
            "FAILED"  { "Red" }
            "SKIPPED" { "Gray" }
            default   { "White" }
        }
        $line = "  [{0}] {1,-22} {2,-10} {3}" -f $row.Status, $row.Step, $row.Target, $row.Note
        Write-Host $line -ForegroundColor $color
    }
    Write-Host "  ================================================" -ForegroundColor Cyan
    Write-Host ""

    # Flag any items needing manual action
    $manual = $script:runSummary | Where-Object { $_.Status -in @("FAILED","WARN") }
    if ($manual) {
        Write-Host "  Items requiring manual attention:" -ForegroundColor Yellow
        foreach ($m in $manual) {
            Write-Host "  - $($m.Step) on $($m.Target): $($m.Note)" -ForegroundColor Yellow
        }
        Write-Host ""
    }
}

# ============================================================
# FIND KEYTOOL
# ============================================================
function Find-Keytool {
    if ($env:JAVA_HOME) {
        $p = Join-Path $env:JAVA_HOME "bin\keytool.exe"
        if (Test-Path $p) { return $p }
    }
    $inPath = Get-Command keytool.exe -ErrorAction SilentlyContinue
    if ($inPath) { return $inPath.Source }

    $customerJavaRoot = "E:\customers\shared\dacs\java"
    if (Test-Path $customerJavaRoot) {
        $p = Join-Path $customerJavaRoot "bin\keytool.exe"
        if (Test-Path $p) { return $p }
        foreach ($sub in Get-ChildItem $customerJavaRoot -Directory -ErrorAction SilentlyContinue) {
            $p = Join-Path $sub.FullName "bin\keytool.exe"
            if (Test-Path $p) { return $p }
        }
    }

    Write-Log "keytool.exe not found automatically." -Level WARN
    $manual = Read-Host "Enter full path to keytool.exe (or leave blank to exit)"
    if ($manual -and (Test-Path $manual)) { return $manual }
    return $null
}

# ============================================================
# READ TOMCAT CONFIG FROM SERVICE + SERVER.XML
# ============================================================
function Get-TomcatKeystoreConfig {
    $svc = Get-Service | Where-Object {
        $_.DisplayName -match "tomcat" -or $_.Name -match "tomcat"
    } | Select-Object -First 1

    if (-not $svc) {
        Write-Log "Service not found by name - searching descriptions..." -Level WARN
        $wmi = Get-WmiObject Win32_Service |
               Where-Object { $_.Description -match "Apache Tomcat" } |
               Select-Object -First 1
        if ($wmi) {
            $svc = Get-Service -Name $wmi.Name -ErrorAction SilentlyContinue
        }
    }

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

    if (-not $tomcatBase -or -not (Test-Path $tomcatBase)) {
        Write-Log "Could not derive Tomcat base from service - trying known paths..." -Level WARN
        foreach ($base in @("E:\customers\shared\dacs\tomcat10","E:\customers\shared\dacs\tomcat","C:\Tomcat")) {
            if (Test-Path (Join-Path $base "conf\server.xml")) {
                $tomcatBase = $base
                Write-Log "Tomcat base from known path: $tomcatBase" -Level INFO
                break
            }
        }
    }

    if (-not $tomcatBase) {
        Write-Log "Tomcat base not found automatically." -Level WARN
        $tomcatBase = Read-Host "Enter Tomcat base path (e.g. E:\customers\shared\dacs\tomcat10)"
        if (-not (Test-Path $tomcatBase)) {
            Write-Log "Path not found: $tomcatBase" -Level ERROR; exit 1
        }
    }

    $serverXml = Join-Path $tomcatBase "conf\server.xml"
    if (-not (Test-Path $serverXml)) {
        Write-Log "server.xml not found at $serverXml" -Level WARN
        $serverXml = Read-Host "Enter full path to server.xml"
        if (-not (Test-Path $serverXml)) {
            Write-Log "server.xml not found at: $serverXml" -Level ERROR; exit 1
        }
    }

    Write-Log "Reading config from: $serverXml" -Level DETAIL
    [xml]$xml  = Get-Content $serverXml
    $connector = $xml.Server.Service.Connector |
                 Where-Object { $_.SSLEnabled -eq "true" -or $_.scheme -eq "https" } |
                 Select-Object -First 1
    if (-not $connector) {
        Write-Log "No HTTPS connector found in server.xml." -Level ERROR; exit 1
    }

    $ksFile  = $connector.keystoreFile
    $ksPass  = $connector.keystorePass
    $ksType  = $connector.keystoreType
    $keyPass = $connector.keyPass
    $keyAlias = $connector.keyAlias

    $sslHost = $connector.SSLHostConfig
    if ($sslHost) {
        $cert = $sslHost.Certificate
        if ($cert.certificateKeystoreFile)     { $ksFile   = $cert.certificateKeystoreFile }
        if ($cert.certificateKeystorePassword) { $ksPass   = $cert.certificateKeystorePassword }
        if ($cert.certificateKeystoreType)     { $ksType   = $cert.certificateKeystoreType }
        if ($cert.certificateKeyPassword)      { $keyPass  = $cert.certificateKeyPassword }
        if ($cert.certificateKeyAlias)         { $keyAlias = $cert.certificateKeyAlias }
    }

    if ($ksFile -and -not [System.IO.Path]::IsPathRooted($ksFile)) {
        $ksFile = Join-Path $tomcatBase $ksFile
    }
    if (-not $ksType) { $ksType = "PKCS12" }

    foreach ($passVar in @("ksPass","keyPass")) {
        $val = Get-Variable $passVar -ValueOnly
        if ($val -match "^\$\{.+\}$") {
            Write-Log "Password is a property placeholder ($val) - enter value manually." -Level WARN
            Set-Variable $passVar (Read-Host "Enter $passVar value")
        }
    }

    $logDir = Join-Path $tomcatBase "logs"
    $valve  = $xml.Server.Service.Engine.Host.Valve |
              Where-Object { $_.className -match "AccessLog" } |
              Select-Object -First 1
    if ($valve -and $valve.directory) {
        $vDir = $valve.directory
        if (-not [System.IO.Path]::IsPathRooted($vDir)) { $vDir = Join-Path $tomcatBase $vDir }
        $logDir = $vDir
    }

    return [PSCustomObject]@{
        KeystoreFile = $ksFile
        KeystoreType = $ksType
        KeystorePass = $ksPass
        KeyPass      = $keyPass
        KeyAlias     = $keyAlias
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
    $safeArgs = @(); $prev = ""
    foreach ($a in $ktArgs) {
        $safeArgs += if ($prev -in @("-storepass","-keypass","-srcstorepass","-deststorepass")) { "****" } else { $a }
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
# VALIDATE KEYSTORE PASSWORD
# ============================================================
function Test-KeystorePassword {
    param($keytool, $config)
    Write-Log "Validating keystore password..." -Level INFO
    $baseArgs = Get-BaseArgs $config
    & $keytool -list @baseArgs 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Log "Keystore password validation failed - check KeystorePass in server.xml." -Level ERROR
        return $false
    }
    Write-Log "Keystore password validated." -Level INFO
    return $true
}

# ============================================================
# CHECK CERT EXPIRY
# ============================================================
function Show-CertExpiry {
    param($keytool, $config)
    $baseArgs = Get-BaseArgs $config
    $details  = & $keytool -list -v @baseArgs 2>&1
    $entries  = $details | Where-Object { $_ -match "Alias name:" }
    if (-not $entries) { return }

    Write-Host ""
    Write-Host "  Current keystore entries:" -ForegroundColor Cyan
    $currentAlias = $null
    foreach ($line in $details) {
        if ($line -match "Alias name:\s*(.+)") {
            $currentAlias = $Matches[1].Trim()
        }
        if ($line -match "Valid from:.+until:\s*(.+)") {
            $expiryStr = $Matches[1].Trim()
            try {
                $expiry  = [datetime]::Parse($expiryStr)
                $daysLeft = ($expiry - (Get-Date)).Days
                $color   = if ($daysLeft -lt 0) { "Red" }
                           elseif ($daysLeft -le $certWarnDays) { "Yellow" }
                           else { "Green" }
                Write-Host ("  {0,-30} Expires: {1:yyyy-MM-dd}  ({2} days)" -f $currentAlias, $expiry, $daysLeft) -ForegroundColor $color
                if ($daysLeft -lt 0) {
                    Write-Log "EXPIRED: Alias '$currentAlias' expired $([Math]::Abs($daysLeft)) days ago." -Level ERROR
                } elseif ($daysLeft -le $certWarnDays) {
                    Write-Log "WARNING: Alias '$currentAlias' expires in $daysLeft days." -Level WARN
                }
            } catch {
                Write-Host "  $currentAlias  - could not parse expiry" -ForegroundColor Gray
            }
        }
    }
    Write-Host ""
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
            if ($t.StartsWith("DNSName:"))   { $sanList.Add("dns:$(($t -split ':',2)[1].Trim())") }
            if ($t.StartsWith("IPAddress:")) { $sanList.Add("ip:$(($t -split ':',2)[1].Trim())") }
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
    $cerName  = "$(Split-Path $config.KeystoreFile -Leaf)-$(Get-Date -Format 'yyyyMMdd').cer"
    $cerPath  = Join-Path $scriptDir $cerName
    $baseArgs = Get-BaseArgs $config
    $rc = Invoke-Keytool $keytool (@(
        "-exportcert", "-alias", $alias, "-file", $cerPath, "-rfc"
    ) + $baseArgs)
    if ($rc -eq 0) {
        $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerPath)
        Write-Log "Cert exported to $cerPath" -Level INFO
        Write-Log "Thumbprint : $($x509.Thumbprint)" -Level INFO
        Write-Log "Subject    : $($x509.Subject)" -Level INFO
        Write-Log "Expires    : $($x509.NotAfter)" -Level INFO
        return $cerPath
    }
    Write-Log "Failed to export cert." -Level ERROR
    return $null
}

# ============================================================
# CLEAN UP OLD .CER AND .CSR FILES IN SCRIPT DIRECTORY
# ============================================================
function Remove-OldCertFiles {
    $cutoff = (Get-Date).AddDays(-$retentionDays)
    foreach ($ext in @("*.cer","*.csr")) {
        $old = Get-ChildItem $scriptDir -Filter $ext -ErrorAction SilentlyContinue |
               Where-Object { $_.LastWriteTime -lt $cutoff }
        if ($old) {
            $old | Remove-Item -Force
            Write-Log "Removed $($old.Count) old $ext file(s) from script directory." -Level INFO
        }
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

    # Count IP hits per log file then find IPs consistent across multiple files
    $ipPerFile = @{}
    $filesRead = 0
    foreach ($f in $logFiles | Select-Object -First 5) {
        $lines = Get-Content $f.FullName -ErrorAction SilentlyContinue |
                 Select-Object -Last $iisLinesToScan
        $seen  = @{}
        foreach ($line in $lines) {
            if ($line -match "^(\d{1,3}(\.\d{1,3}){3})") {
                $ip = $Matches[1]
                if (-not $seen[$ip]) {
                    $ipPerFile[$ip] = ($ipPerFile[$ip] -as [int]) + 1
                    $seen[$ip] = $true
                }
            }
        }
        $filesRead++
    }

    if ($ipPerFile.Count -eq 0) {
        Write-Log "No IPs found in access logs." -Level WARN
        return $null
    }

    # Sort by consistency (appears in most log files) then frequency
    $topIPs = $ipPerFile.GetEnumerator() |
              Sort-Object Value -Descending |
              Select-Object -First 5

    Write-Host ""
    Write-Host "  IPs found consistently across log files:" -ForegroundColor Cyan
    $i = 1
    foreach ($entry in $topIPs) {
        Write-Host "  [$i] $($entry.Key)  (seen in $($entry.Value) of $filesRead log files)"
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
# IMPORT CERT TO IIS TRUSTED ROOT - admin console, no WinRM
# ============================================================
function Import-CertToIIS {
    param([string]$iisServer, [string]$cerPath)
    Write-Log "Importing cert to IIS Trusted Root on $iisServer..." -Level INFO

    # Verify admin share reachable
    if (-not (Test-Path "\\$iisServer\C$")) {
        Write-Log "Cannot reach \\$iisServer\C$ - check admin share access." -Level ERROR
        Add-Summary "IIS Cert Import" $iisServer "FAILED" "Admin share unreachable"
        return $false
    }

    $remoteTemp    = "\\$iisServer\C$\Windows\Temp"
    $remoteCer     = "$remoteTemp\$(Split-Path $cerPath -Leaf)"
    $remoteCerLocal = "C:\Windows\Temp\$(Split-Path $cerPath -Leaf)"
    $taskName      = "TomcatCertImport_$ts"

    if ($WhatIf) {
        Write-Host "  [WHATIF] Would copy $cerPath to $remoteCer" -ForegroundColor Magenta
        Write-Host "  [WHATIF] Would run certutil -addstore Root on $iisServer" -ForegroundColor Magenta
        Add-Summary "IIS Cert Import" $iisServer "OK" "WhatIf"
        return $true
    }

    try {
        Copy-Item $cerPath $remoteCer -Force -ErrorAction Stop
        Write-Log "Cert copied to $remoteCer" -Level INFO
    } catch {
        Write-Log "Failed to copy cert to $remoteTemp : $_" -Level ERROR
        Add-Summary "IIS Cert Import" $iisServer "FAILED" "Copy failed: $_"
        return $false
    }

    $cmd = "certutil -addstore -f Root `"$remoteCerLocal`""
    & schtasks.exe /create /s $iisServer /tn $taskName /ru "SYSTEM" `
        /sc ONCE /st 00:00 /tr "cmd.exe /c $cmd" /f 2>&1 |
        ForEach-Object { Write-Log $_ -Level DETAIL }
    & schtasks.exe /run /s $iisServer /tn $taskName 2>&1 |
        ForEach-Object { Write-Log $_ -Level DETAIL }
    Start-Sleep -Seconds 5
    & schtasks.exe /delete /s $iisServer /tn $taskName /f 2>&1 |
        ForEach-Object { Write-Log $_ -Level DETAIL }
    Remove-Item $remoteCer -Force -ErrorAction SilentlyContinue

    Write-Log "Cert import task completed on $iisServer - verify in certlm.msc" -Level INFO
    Add-Summary "IIS Cert Import" $iisServer "OK" "Verify in certlm.msc"
    return $true
}

# ============================================================
# WAIT FOR SERVICE STATE
# ============================================================
function Wait-ServiceState {
    param([string]$server, [string]$svcName, [string]$desiredState, [int]$timeoutSec)
    $elapsed = 0
    while ($elapsed -lt $timeoutSec) {
        $query = & sc.exe "\\$server" query $svcName 2>&1
        if ($query -match $desiredState) { return $true }
        Start-Sleep -Seconds 3
        $elapsed += 3
    }
    return $false
}

# ============================================================
# FIND TOMCAT SERVICE + KEYSTORE PATH ON REMOTE SERVER
# ============================================================
function Get-RemoteTomcatInfo {
    param([string]$targetServer, [string]$localKeystoreLeaf)

    # Check server is reachable first
    if (-not (Test-Path "\\$targetServer\C$")) {
        Write-Log "Cannot reach \\$targetServer\C$ - server may be offline or admin share blocked." -Level ERROR -Server $targetServer
        return $null
    }

    # WMI query with timeout handling
    $wmiSvc = $null
    try {
        $job = Start-Job {
            param($s)
            Get-WmiObject Win32_Service -ComputerName $s -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "tomcat" -or $_.DisplayName -match "tomcat" } |
            Select-Object -First 1
        } -ArgumentList $targetServer
        $done = Wait-Job $job -Timeout $wmiTimeout
        if ($done) {
            $wmiSvc = Receive-Job $job
        } else {
            Write-Log "WMI query timed out on $targetServer" -Level WARN -Server $targetServer
        }
        Remove-Job $job -Force
    } catch {
        Write-Log "WMI query failed on ${targetServer}: $_" -Level WARN -Server $targetServer
    }

    # Fall back to description search
    if (-not $wmiSvc) {
        try {
            $job = Start-Job {
                param($s)
                Get-WmiObject Win32_Service -ComputerName $s -ErrorAction SilentlyContinue |
                Where-Object { $_.Description -match "Apache Tomcat" } |
                Select-Object -First 1
            } -ArgumentList $targetServer
            $done = Wait-Job $job -Timeout $wmiTimeout
            if ($done) { $wmiSvc = Receive-Job $job }
            Remove-Job $job -Force
        } catch {
            Write-Log "WMI description search failed on ${targetServer}: $_" -Level WARN -Server $targetServer
        }
    }

    $svcName    = $null
    $tomcatBase = $null
    $ksPath     = $null

    if ($wmiSvc) {
        $svcName    = $wmiSvc.Name
        $exePath    = $wmiSvc.PathName.Trim('"') -replace "\s.+$", ""
        $tomcatBase = Split-Path (Split-Path $exePath)
        Write-Log "Service: $svcName  Base: $tomcatBase" -Level INFO -Server $targetServer

        $uncConf = "\\$targetServer\$($tomcatBase -replace ':','$')\conf\server.xml"
        if (Test-Path $uncConf) {
            [xml]$xml  = Get-Content $uncConf -ErrorAction SilentlyContinue
            $conn      = $xml.Server.Service.Connector |
                         Where-Object { $_.SSLEnabled -eq "true" -or $_.scheme -eq "https" } |
                         Select-Object -First 1
            if ($conn) {
                $ksFile = $conn.keystoreFile
                if ($conn.SSLHostConfig -and $conn.SSLHostConfig.Certificate.certificateKeystoreFile) {
                    $ksFile = $conn.SSLHostConfig.Certificate.certificateKeystoreFile
                }
                if ($ksFile) {
                    if (-not [System.IO.Path]::IsPathRooted($ksFile)) {
                        $ksFile = Join-Path $tomcatBase $ksFile
                    }
                    $ksPath = $ksFile
                    Write-Log "Keystore from server.xml: $ksPath" -Level INFO -Server $targetServer
                }
            }
        }
    }

    # Fall back to known paths
    if (-not $ksPath) {
        Write-Log "Trying known Tomcat paths..." -Level WARN -Server $targetServer
        foreach ($base in @("E:\customers\shared\dacs\tomcat10","E:\customers\shared\dacs\tomcat")) {
            $uncBase = "\\$targetServer\$($base -replace ':','$')"
            if (Test-Path $uncBase) {
                $tomcatBase = $base
                $uncConf    = "$uncBase\conf\server.xml"
                if (Test-Path $uncConf) {
                    [xml]$xml = Get-Content $uncConf -ErrorAction SilentlyContinue
                    $conn     = $xml.Server.Service.Connector |
                                Where-Object { $_.SSLEnabled -eq "true" -or $_.scheme -eq "https" } |
                                Select-Object -First 1
                    if ($conn) {
                        $ksFile = $conn.keystoreFile
                        if ($conn.SSLHostConfig -and $conn.SSLHostConfig.Certificate.certificateKeystoreFile) {
                            $ksFile = $conn.SSLHostConfig.Certificate.certificateKeystoreFile
                        }
                        if ($ksFile) {
                            if (-not [System.IO.Path]::IsPathRooted($ksFile)) {
                                $ksFile = Join-Path $tomcatBase $ksFile
                            }
                            $ksPath = $ksFile
                        }
                    }
                }
                if (-not $ksPath) {
                    $ksPath = Join-Path $tomcatBase "conf\$localKeystoreLeaf"
                }
                Write-Log "Using known path: $tomcatBase  Keystore: $ksPath" -Level INFO -Server $targetServer
                break
            }
        }
    }

    if (-not $ksPath) { return $null }

    return [PSCustomObject]@{
        ServiceName  = $svcName
        TomcatBase   = $tomcatBase
        KeystorePath = $ksPath
    }
}

# ============================================================
# PUSH KEYSTORE TO SAN SERVER
# ============================================================
function Push-KeystoreToSanServer {
    param([string]$targetServer, [string]$localKeystorePath)
    Write-Log "Starting push to $targetServer..." -Level INFO -Server $targetServer

    $remoteInfo = Get-RemoteTomcatInfo -targetServer $targetServer `
                  -localKeystoreLeaf (Split-Path $localKeystorePath -Leaf)

    if (-not $remoteInfo) {
        Write-Log "Could not determine remote config - skipping $targetServer." -Level ERROR -Server $targetServer
        Add-Summary "Keystore Push" $targetServer "FAILED" "Could not determine remote config"
        return $false
    }

    $ksLeaf    = Split-Path $remoteInfo.KeystorePath -Leaf
    $remoteDir = Split-Path $remoteInfo.KeystorePath
    $uncDir    = "\\$targetServer\$($remoteDir -replace ':','$')"
    $uncKs     = "$uncDir\$ksLeaf"

    Write-Log "Remote keystore: $($remoteInfo.KeystorePath)" -Level INFO -Server $targetServer
    Write-Log "Service        : $($remoteInfo.ServiceName)" -Level INFO -Server $targetServer

    try {
        # Backup
        if (Test-Path $uncKs) {
            $bkDest = "$uncKs.backup.$ts"
            if ($WhatIf) {
                Write-Host "  [WHATIF] Would backup $uncKs to $bkDest" -ForegroundColor Magenta
            } else {
                Copy-Item $uncKs $bkDest -Force
                Write-Log "Remote keystore backed up to $bkDest" -Level INFO -Server $targetServer
            }
        }

        # Copy
        if ($WhatIf) {
            Write-Host "  [WHATIF] Would copy $localKeystorePath to $uncKs" -ForegroundColor Magenta
        } else {
            Copy-Item $localKeystorePath $uncKs -Force -ErrorAction Stop
            Write-Log "Keystore copied to $uncKs" -Level INFO -Server $targetServer
        }

        # Restart service
        if ($remoteInfo.ServiceName) {
            if ($WhatIf) {
                Write-Host "  [WHATIF] Would restart $($remoteInfo.ServiceName) on $targetServer" -ForegroundColor Magenta
            } else {
                Write-Log "Stopping $($remoteInfo.ServiceName)..." -Level INFO -Server $targetServer
                & sc.exe "\\$targetServer" stop $remoteInfo.ServiceName 2>&1 |
                    ForEach-Object { Write-Log $_ -Level DETAIL -Server $targetServer }

                $stopped = Wait-ServiceState $targetServer $remoteInfo.ServiceName "STOPPED" $svcStopTimeout
                if (-not $stopped) {
                    Write-Log "Service did not stop within $svcStopTimeout seconds." -Level WARN -Server $targetServer
                }

                & sc.exe "\\$targetServer" start $remoteInfo.ServiceName 2>&1 |
                    ForEach-Object { Write-Log $_ -Level DETAIL -Server $targetServer }

                $started = Wait-ServiceState $targetServer $remoteInfo.ServiceName "RUNNING" $svcStartTimeout
                if ($started) {
                    Write-Log "Service is running." -Level INFO -Server $targetServer
                    Add-Summary "Keystore Push" $targetServer "OK" "Service restarted"
                } else {
                    Write-Log "Service did not start within $svcStartTimeout seconds - verify manually." -Level WARN -Server $targetServer
                    Add-Summary "Keystore Push" $targetServer "WARN" "Service may not have started"
                }
            }
        } else {
            Write-Log "No service found - restart Tomcat manually on $targetServer." -Level WARN -Server $targetServer
            Add-Summary "Keystore Push" $targetServer "WARN" "Keystore copied - restart Tomcat manually"
        }
        return $true
    } catch {
        Write-Log "Push failed for ${targetServer}: $_" -Level ERROR -Server $targetServer
        Add-Summary "Keystore Push" $targetServer "FAILED" "$_"
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
        Add-Summary "Local Restart" $env:COMPUTERNAME "WARN" "Service name not detected"
        return
    }
    $restart = (Read-Host "  Restart Tomcat service '$($config.ServiceName)' now? (y/n)").ToLower()
    if ($restart -ne "y") {
        Write-Log "Tomcat restart skipped." -Level WARN
        Add-Summary "Local Restart" $env:COMPUTERNAME "SKIPPED" "User skipped restart"
        return
    }
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would restart service: $($config.ServiceName)" -ForegroundColor Magenta
        Add-Summary "Local Restart" $env:COMPUTERNAME "OK" "WhatIf"
        return
    }
    try {
        Write-Log "Stopping $($config.ServiceName)..." -Level INFO
        Stop-Service -Name $config.ServiceName -Force -ErrorAction Stop
        $stopped = Wait-ServiceState $env:COMPUTERNAME $config.ServiceName "STOPPED" $svcStopTimeout
        if (-not $stopped) {
            Write-Log "Service did not stop within $svcStopTimeout seconds." -Level WARN
        }
        Start-Service -Name $config.ServiceName -ErrorAction Stop
        $started = Wait-ServiceState $env:COMPUTERNAME $config.ServiceName "RUNNING" $svcStartTimeout
        if ($started) {
            Write-Log "Service is running." -Level INFO
            Add-Summary "Local Restart" $env:COMPUTERNAME "OK" ""
        } else {
            Write-Log "Service did not start within $svcStartTimeout seconds - verify manually." -Level WARN
            Add-Summary "Local Restart" $env:COMPUTERNAME "WARN" "Did not start within timeout"
        }
    } catch {
        Write-Log "Failed to restart service: $_" -Level ERROR
        Add-Summary "Local Restart" $env:COMPUTERNAME "FAILED" "$_"
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
        if ($h -ne $localHost) { $servers += $h }
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
            -targetServer      $servers[$idx] `
            -localKeystorePath $config.KeystoreFile
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

    # 1. Export cert
    $cerPath = Export-TomcatCert $keytool $config $alias
    if ($cerPath) {
        Add-Summary "Cert Export" $env:COMPUTERNAME "OK" $cerPath
    } else {
        Add-Summary "Cert Export" $env:COMPUTERNAME "FAILED" ""
    }

    # 2. IIS import
    if ($cerPath) {
        $iisServer = Get-IISServerFromLog -logDir $config.LogDir
        if ($iisServer) {
            Import-CertToIIS -iisServer $iisServer -cerPath $cerPath
        } else {
            Write-Log "IIS server not identified - import cert manually from: $cerPath" -Level WARN
            Add-Summary "IIS Cert Import" "(manual)" "SKIPPED" "Copy $cerPath to IIS server"
        }
    }

    # 3. Push to SAN servers
    $baseArgs = Get-BaseArgs $config
    $details  = & $keytool -list -v @baseArgs 2>&1
    $sanList  = Get-CertSANs $details
    if ($sanList.Count -gt 0) {
        $push = (Read-Host "  Push updated keystore to other SAN servers? (y/n)").ToLower()
        if ($push -eq "y") {
            Show-SanServerMenu -config $config -sanList $sanList -mode "push"
        } else {
            Add-Summary "SAN Push" "(skipped)" "SKIPPED" "User skipped"
        }
    }

    # 4. Restart local Tomcat
    Invoke-TomcatRestart $config

    # 5. Clean up old cert files
    Remove-OldCertFiles

    # 6. Show summary
    Show-Summary
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
Write-Host "  Tomcat Keystore Management Script v7$(if($WhatIf){' [WHATIF]'})" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
if ($WhatIf) { Write-Host "  WHATIF MODE - no changes will be made`n" -ForegroundColor Magenta }

Write-Log "--- Script started. Log: $logFile ---" -Level INFO

$keytool = Find-Keytool
if (-not $keytool) {
    Write-Log "keytool.exe not found. Exiting." -Level ERROR; exit 1
}
Write-Log "keytool: $keytool" -Level INFO

$config   = Get-TomcatKeystoreConfig
$ksExists = Test-Path $config.KeystoreFile

Write-Host ""
Write-Host "  Keystore : $($config.KeystoreFile)$(if(-not $ksExists){' (not found)'})" -ForegroundColor White
Write-Host "  Type     : $($config.KeystoreType)" -ForegroundColor White
Write-Host "  Service  : $(if($config.ServiceName){$config.ServiceName}else{'(not detected)'})" -ForegroundColor White
Write-Host "  Alias    : $(if($config.KeyAlias){$config.KeyAlias}else{'(not set in server.xml)'})" -ForegroundColor White
Write-Host "  Log Dir  : $($config.LogDir)" -ForegroundColor White
Write-Host "  Log      : $logFile" -ForegroundColor White

# Validate password and show cert expiry before menu
if ($ksExists) {
    if (-not (Test-KeystorePassword $keytool $config)) { exit 1 }
    Show-CertExpiry $keytool $config
}

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

    # Warn if alias does not match server.xml keyAlias
    if ($config.KeyAlias -and $aliasName -ne $config.KeyAlias) {
        Write-Host ""
        Write-Host "  WARNING: Entered alias '$aliasName' does not match keyAlias '$($config.KeyAlias)' in server.xml." -ForegroundColor Yellow
        Write-Host "  Tomcat will use '$($config.KeyAlias)' - the new cert may not be loaded." -ForegroundColor Yellow
        $cont = (Read-Host "  Continue anyway? (y/n)").ToLower()
        if ($cont -ne "y") { exit 0 }
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

    $genArgs = @("-genkeypair","-alias",$aliasName,"-keyalg",$keyAlg) +
               $keySizeArg +
               @("-validity",$validity,"-dname",$dNameToUse,"-ext",$sanExt,"-keypass",$config.KeyPass) +
               $baseArgs

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
        Write-Log "Alias '$aliasName' not found. Generate a key pair first (option U)." -Level ERROR; exit 1
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
        Show-Summary
    }
}

# ============================================================
# X - COPY CERT TO SAN SERVER
# ============================================================
elseif ($choice -eq "X") {
    Write-Log "User selected [Copy cert to SAN server]." -Level INFO
    Invoke-CopyCertToSanServer -config $config -keytool $keytool
    Show-Summary
}

else {
    Write-Log "Invalid option selected." -Level ERROR
}

Write-Log "--- Script complete ---" -Level INFO

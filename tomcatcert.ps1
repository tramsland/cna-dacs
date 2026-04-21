#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Tomcat Certificate Expiry Scanner + Remote Management
.DESCRIPTION
    Reads servers.txt (same zone/group format as the service checker), connects
    to each server in parallel, parses Tomcat server.xml, reads every alias in
    the keystore via keytool, and reports expiry status. Flags certs expiring
    within 60 days as WARN, already-expired as CRITICAL. After the scan you can
    optionally pick a server and run full keystore management (renew, CSR,
    import, rollback) against it remotely.
.PARAMETER WarnDays
    Days-to-expiry threshold for WARN status. Default: 60.
.PARAMETER SkipCredentialPrompt
    Skip the alternate-credentials prompt (required for non-interactive /
    remote execution contexts where no console is attached).
.PARAMETER WhatIf
    Show what management actions would be taken without making changes.
.NOTES
    - Requires WinRM / PowerShell remoting to target servers
    - keytool.exe must be present on each remote server
    - servers.txt format:
        [ZoneName]
        server1.fqdn.com
        server2.fqdn.com
#>
param(
    [int]   $WarnDays             = 60,
    [switch]$SkipCredentialPrompt,
    [switch]$WhatIf
)

# ============================================================
# CONFIGURATION
# ============================================================
$scriptDir       = Split-Path -Parent $MyInvocation.MyCommand.Definition
$configFile      = Join-Path $scriptDir "servers.txt"
$outputDir       = Join-Path $scriptDir "cert-reports"
$maxParallelJobs = 5
$jobTimeoutSec   = 120

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile   = Join-Path $outputDir "CertCheck_$timestamp.log"
$htmlFile  = Join-Path $outputDir "CertCheck_$timestamp.html"

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

$serverCount = ($serverGroups.Values | Measure-Object -Property Count -Sum).Sum
if ($serverCount -eq 0) {
    Write-Host "ERROR: No servers found in $configFile" -ForegroundColor Red
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
# REMOTE SCAN SCRIPT BLOCK
# ============================================================
$scanScriptBlock = {
    param(
        [string]$ComputerName,
        [string]$GroupName,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$WarnDays
    )

    $result = [PSCustomObject]@{
        ComputerName  = $ComputerName
        GroupName     = $GroupName
        OverallStatus = "OK"
        Error         = $null
        Certs         = [System.Collections.Generic.List[PSCustomObject]]::new()
        TomcatBase    = $null
        ServiceName   = $null
        KeystoreFile  = $null
        KeystoreType  = $null
        Output        = [System.Collections.Generic.List[string]]::new()
    }

    # ── Ping ─────────────────────────────────────────────────────────────────
    $pingOk = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (-not $pingOk) {
        $result.Error         = "Host unreachable (no ping response)"
        $result.OverallStatus = "DOWN"
        $result.Output.Add("  ERROR: $($result.Error)")
        return $result
    }

    # ── Remote scriptblock executed on target server ──────────────────────────
    $icParams = @{
        ComputerName  = $ComputerName
        ErrorAction   = "Stop"
        ArgumentList  = $WarnDays
        ScriptBlock   = {
            param([int]$WarnDays)

            $out = [System.Collections.Generic.List[PSCustomObject]]::new()

            # ── Find keytool ──────────────────────────────────────────────────
            function Find-Keytool {
                $dacsJava = "E:\customers\shared\dacs\java"
                if (Test-Path $dacsJava) {
                    $f = Get-ChildItem -Path $dacsJava -Recurse -Filter "keytool.exe" -ErrorAction SilentlyContinue |
                         Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($f) { return $f.FullName }
                }
                if ($env:JAVA_HOME) {
                    $p = Join-Path $env:JAVA_HOME "bin\keytool.exe"
                    if (Test-Path $p) { return $p }
                }
                $inPath = Get-Command keytool.exe -ErrorAction SilentlyContinue
                if ($inPath) { return $inPath.Source }
                foreach ($base in @(
                    "C:\Program Files\Java","C:\Program Files\Eclipse Adoptium",
                    "C:\Program Files\Microsoft","C:\Program Files\OpenJDK","C:\Program Files\Zulu"
                )) {
                    $f = Get-ChildItem -Path $base -Recurse -Filter "keytool.exe" -ErrorAction SilentlyContinue |
                         Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($f) { return $f.FullName }
                }
                return $null
            }

            # ── Find Tomcat + server.xml ──────────────────────────────────────
            function Get-TomcatInfo {
                $svc = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
                       Where-Object { $_.Name -match "^tomcat" -or $_.DisplayName -match "Apache Tomcat" } |
                       Select-Object -First 1

                $installPath = $null
                $svcName     = $null

                if ($svc) {
                    $svcName = $svc.Name
                    $exePath = ($svc.PathName -replace '^"([^"]+)".*$','$1' -split '\s+//')[0].Trim('"')
                    if (Test-Path $exePath) {
                        $installPath = Split-Path (Split-Path $exePath -Parent) -Parent
                    }
                }

                if (-not $installPath) {
                    foreach ($p in @("E:\customers\shared\dacs\tomcat10","E:\customers\shared\dacs\tomcat")) {
                        if (Test-Path $p) { $installPath = $p; break }
                    }
                }
                if (-not $installPath) { return $null }

                $serverXml = Join-Path $installPath "conf\server.xml"
                if (-not (Test-Path $serverXml)) {
                    $found = Get-ChildItem -Path $installPath -Recurse -Filter "server.xml" -ErrorAction SilentlyContinue |
                             Select-Object -First 1
                    if ($found) {
                        $serverXml   = $found.FullName
                        $installPath = Split-Path (Split-Path $serverXml) -Parent
                    } else { return $null }
                }

                return [PSCustomObject]@{
                    InstallPath = $installPath
                    ServiceName = $svcName
                    ServerXml   = $serverXml
                }
            }

            # ── Parse keystore config from server.xml ─────────────────────────
            function Get-KeystoreConfig {
                param($tomcatInfo)
                [xml]$xml = Get-Content $tomcatInfo.ServerXml -ErrorAction Stop

                $ksFile = $null; $ksPass = $null; $ksType = "JKS"; $ksAlias = $null

                $certElem = $xml.SelectNodes("//Certificate") | Select-Object -First 1
                if ($certElem) {
                    $ksFile  = $certElem.certificateKeystoreFile
                    $ksPass  = $certElem.certificateKeystorePassword
                    $ksType  = if ($certElem.certificateKeystoreType) { $certElem.certificateKeystoreType } else { "PKCS12" }
                    $ksAlias = $certElem.certificateKeyAlias
                }

                if (-not $ksFile) {
                    $conn = $xml.SelectNodes("//Connector[@SSLEnabled='true']") | Select-Object -First 1
                    if ($conn) {
                        $ksFile  = $conn.keystoreFile
                        $ksPass  = $conn.keystorePass
                        $ksType  = if ($conn.keystoreType) { $conn.keystoreType } else { "JKS" }
                        $ksAlias = $conn.keyAlias
                    }
                }

                if (-not $ksFile) { return $null }

                if (-not [System.IO.Path]::IsPathRooted($ksFile)) {
                    $ksFile = Join-Path $tomcatInfo.InstallPath $ksFile
                }
                if ($ksFile -match "\.(p12|pfx)$" -and $ksType -eq "JKS") { $ksType = "PKCS12" }

                return [PSCustomObject]@{
                    KeystoreFile = $ksFile
                    KeystorePass = $ksPass
                    KeystoreType = $ksType
                    KeyAlias     = $ksAlias
                }
            }

            # ── Parse keytool -list -v output into cert objects ───────────────
            function Parse-KeytoolOutput {
                param([string[]]$lines, [int]$WarnDays)
                $certs   = [System.Collections.Generic.List[PSCustomObject]]::new()
                $current = $null
                $inSan   = $false

                foreach ($line in $lines) {
                    $t = $line.Trim()

                    if ($t -match "^Alias name:\s*(.+)") {
                        if ($current) { $certs.Add($current) }
                        $current = [PSCustomObject]@{
                            Alias      = $Matches[1].Trim()
                            EntryType  = ""
                            Subject    = ""
                            Issuer     = ""
                            NotBefore  = ""
                            NotAfter   = ""
                            DaysLeft   = $null
                            Status     = "OK"
                            Algorithm  = ""
                            SANs       = [System.Collections.Generic.List[string]]::new()
                            SerialNo   = ""
                        }
                        $inSan = $false
                        continue
                    }

                    if (-not $current) { continue }

                    if ($t -match "^Entry type:\s*(.+)")          { $current.EntryType = $Matches[1].Trim() }
                    if ($t -match "^Owner:\s*(.+)")               { $current.Subject   = $Matches[1].Trim() }
                    if ($t -match "^Issuer:\s*(.+)")              { $current.Issuer    = $Matches[1].Trim() }
                    if ($t -match "^Serial number:\s*(.+)")       { $current.SerialNo  = $Matches[1].Trim() }
                    if ($t -match "Signature algorithm name:\s*(.+)") { $current.Algorithm = $Matches[1].Trim() }
                    if ($t -match "^Valid from:\s*(.+)\s+until:\s*(.+)") {
                        $current.NotBefore = $Matches[1].Trim()
                        $current.NotAfter  = $Matches[2].Trim()
                        try {
                            $exp              = [datetime]::Parse($current.NotAfter)
                            $current.DaysLeft = [math]::Floor(($exp - (Get-Date)).TotalDays)
                            $current.Status   = if ($current.DaysLeft -lt 0)        { "EXPIRED"  }
                                                elseif ($current.DaysLeft -lt $WarnDays) { "WARN"     }
                                                else                                  { "OK"       }
                        } catch {}
                    }

                    if ($t -match "SubjectAlternativeName") { $inSan = $true; continue }
                    if ($inSan) {
                        if ($t -match "^DNSName:\s*(.+)")   { $current.SANs.Add("DNS:$($Matches[1].Trim())") }
                        if ($t -match "^IPAddress:\s*(.+)") { $current.SANs.Add("IP:$($Matches[1].Trim())")  }
                        if ($t -eq "]" -or ($t -eq "" -and $current.SANs.Count -gt 0)) { $inSan = $false }
                    }
                }

                if ($current) { $certs.Add($current) }
                return $certs
            }

            # ── Main remote logic ─────────────────────────────────────────────
            $keytool    = Find-Keytool
            $tomcatInfo = Get-TomcatInfo

            if (-not $keytool)    { return [PSCustomObject]@{ Error = "keytool.exe not found"; Certs = $null; TomcatInfo = $null; KsConfig = $null } }
            if (-not $tomcatInfo) { return [PSCustomObject]@{ Error = "Tomcat installation not found"; Certs = $null; TomcatInfo = $null; KsConfig = $null } }

            $ksConfig = Get-KeystoreConfig $tomcatInfo
            if (-not $ksConfig)   { return [PSCustomObject]@{ Error = "Keystore config not found in server.xml"; Certs = $null; TomcatInfo = $tomcatInfo; KsConfig = $null } }
            if (-not (Test-Path $ksConfig.KeystoreFile)) {
                return [PSCustomObject]@{ Error = "Keystore file not found: $($ksConfig.KeystoreFile)"; Certs = $null; TomcatInfo = $tomcatInfo; KsConfig = $ksConfig }
            }

            $ktArgs  = @("-list","-v","-keystore",$ksConfig.KeystoreFile,"-storetype",$ksConfig.KeystoreType,"-storepass",$ksConfig.KeystorePass)
            $ktOut   = & $keytool $ktArgs 2>&1
            $certs   = Parse-KeytoolOutput -lines $ktOut -WarnDays $WarnDays

            return [PSCustomObject]@{
                Error      = $null
                Certs      = $certs
                TomcatInfo = $tomcatInfo
                KsConfig   = $ksConfig
            }
        }
    }

    if ($Credential) { $icParams["Credential"] = $Credential }

    try {
        $remote = Invoke-Command @icParams

        $result.TomcatBase   = $remote.TomcatInfo?.InstallPath
        $result.ServiceName  = $remote.TomcatInfo?.ServiceName
        $result.KeystoreFile = $remote.KsConfig?.KeystoreFile
        $result.KeystoreType = $remote.KsConfig?.KeystoreType

        if ($remote.Error) {
            $result.Error         = $remote.Error
            $result.OverallStatus = "ERROR"
            $result.Output.Add("  ERROR: $($remote.Error)")
            return $result
        }

        if (-not $remote.Certs -or $remote.Certs.Count -eq 0) {
            $result.Error         = "No certificate aliases found in keystore"
            $result.OverallStatus = "WARN"
            $result.Output.Add("  WARN: $($result.Error)")
            return $result
        }

        foreach ($cert in $remote.Certs) {
            $result.Certs.Add($cert)
            if ($cert.Status -eq "EXPIRED")                           { $result.OverallStatus = "CRITICAL" }
            elseif ($cert.Status -eq "WARN" -and $result.OverallStatus -eq "OK") { $result.OverallStatus = "WARN" }
        }

        $result.Output.Add("  Keystore : $($result.KeystoreFile)")
        $result.Output.Add("  Type     : $($result.KeystoreType)")
        $result.Output.Add("  Service  : $(if($result.ServiceName){$result.ServiceName}else{'(not detected)'})")
        $result.Output.Add("  Aliases  : $($result.Certs.Count)")
        foreach ($cert in $result.Certs) {
            $tag = switch ($cert.Status) { "EXPIRED" { "[EXPIRED]" } "WARN" { "[WARN]" } default { "[OK]" } }
            $daysText = if ($null -ne $cert.DaysLeft) {
                if ($cert.DaysLeft -lt 0) { "EXPIRED $([math]::Abs($cert.DaysLeft)) days ago" }
                else { "$($cert.DaysLeft) days remaining" }
            } else { "unknown expiry" }
            $result.Output.Add("")
            $result.Output.Add("  ── Alias: $($cert.Alias) $tag")
            $result.Output.Add("     Subject  : $($cert.Subject)")
            $result.Output.Add("     Issuer   : $($cert.Issuer)")
            $result.Output.Add("     Expires  : $($cert.NotAfter)  ($daysText)")
            $result.Output.Add("     Algorithm: $($cert.Algorithm)")
            if ($cert.SANs.Count -gt 0) {
                $result.Output.Add("     SANs     : $($cert.SANs -join ', ')")
            }
        }

    } catch {
        $result.Error         = "Invoke-Command failed: $_"
        $result.OverallStatus = "ERROR"
        $result.Output.Add("  ERROR: $($result.Error)")
    }

    return $result
}

# ============================================================
# RUN PARALLEL SCAN
# ============================================================
Clear-Host
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Tomcat Certificate Expiry Scanner" -ForegroundColor Cyan
Write-Host "  Warn threshold : $WarnDays days" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

Write-Log "Tomcat Certificate Expiry Scanner started" -Color Cyan
Write-Log "Servers: $serverCount | Warn threshold: $WarnDays days" -Color Gray
Write-Log "Log: $logFile" -Color Gray
Write-Log ""

$jobs = [System.Collections.Generic.List[hashtable]]::new()
foreach ($group in $serverGroups.Keys) {
    foreach ($server in $serverGroups[$group]) {
        while ((Get-Job -State Running).Count -ge $maxParallelJobs) { Start-Sleep -Milliseconds 500 }
        $j = Start-Job -ScriptBlock $scanScriptBlock `
                 -ArgumentList $server, $group, $Credential, $WarnDays
        $jobs.Add(@{ Job = $j; Server = $server; Group = $group })
        Write-Log "Queued: [$group] $server" -Color Gray
    }
}

Write-Log "Scanning $serverCount server(s) in parallel..." -Color Yellow
Write-Log ""

foreach ($entry in $jobs) {
    $finished = $entry.Job | Wait-Job -Timeout $jobTimeoutSec
    if (-not $finished) {
        Write-Log "TIMEOUT: [$($entry.Group)] $($entry.Server)" -Color Red
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

# ============================================================
# CONSOLE OUTPUT
# ============================================================
$zoneSummary = [ordered]@{}
$prevGroup   = $null

foreach ($result in ($results | Sort-Object GroupName, ComputerName)) {
    $grp = $result.GroupName
    if (-not $zoneSummary.Contains($grp)) {
        $zoneSummary[$grp] = @{ OK=0; WARN=0; CRITICAL=0; ERROR=0; DOWN=0 }
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
        "CRITICAL" { "Red" } "WARN" { "Yellow" } "ERROR" { "Red" } "DOWN" { "Red" } default { "Cyan" }
    }
    Write-Log "" -Color White
    Write-Log "========================================"  -Color $headerColor
    Write-Log "Zone   : $($result.GroupName)" -Color Magenta
    Write-Log "Server : $($result.ComputerName)  [$($result.OverallStatus)]" -Color $headerColor

    foreach ($line in $result.Output) {
        $color = "White"
        if     ($line -match "\[EXPIRED\]")              { $color = "Red"    }
        elseif ($line -match "\[WARN\]")                 { $color = "Yellow" }
        elseif ($line -match "\[OK\]")                   { $color = "Green"  }
        elseif ($line -match "ERROR:")                   { $color = "Red"    }
        elseif ($line -match "Expires\s*:")              { $color = "Cyan"   }
        elseif ($line -match "── Alias:")                { $color = "Cyan"   }
        Write-Log $line -Color $color
    }
    Write-Log "========================================"  -Color $headerColor
}

# Zone rollup
Write-Log "" -Color White
Write-Log "======== Zone Rollup ========" -Color Cyan
foreach ($grp in $zoneSummary.Keys) {
    $s   = $zoneSummary[$grp]
    $tot = $s.OK + $s.WARN + $s.CRITICAL + $s.ERROR + $s.DOWN
    $col = if ($s.CRITICAL -gt 0 -or $s.DOWN -gt 0 -or $s.ERROR -gt 0) { "Red" }
           elseif ($s.WARN -gt 0) { "Yellow" }
           else { "Green" }
    Write-Log ("  {0,-40} : {1} OK  {2} WARN  {3} CRITICAL  {4} ERROR  (of {5})" -f `
        $grp, $s.OK, $s.WARN, $s.CRITICAL, ($s.ERROR + $s.DOWN), $tot) -Color $col
}
Write-Log "=============================" -Color Cyan

# ============================================================
# HTML REPORT
# ============================================================
$zoneRollupHtml = ""
foreach ($grp in $zoneSummary.Keys) {
    $s   = $zoneSummary[$grp]
    $cls = if ($s.CRITICAL -gt 0 -or $s.DOWN -gt 0 -or $s.ERROR -gt 0) { "critical" }
           elseif ($s.WARN -gt 0) { "warn" }
           else { "ok" }
    $zoneRollupHtml += "<div class='zone-pill $cls'>$grp &nbsp; OK:$($s.OK) WARN:$($s.WARN) CRITICAL:$($s.CRITICAL) ERROR:$($s.ERROR + $s.DOWN)</div>"
}

$tableRows = ""
foreach ($result in ($results | Sort-Object GroupName, ComputerName)) {
    $serverCls = switch ($result.OverallStatus) {
        "CRITICAL" { "critical" } "WARN" { "warn" } "ERROR" { "error" } "DOWN" { "error" } default { "ok" }
    }

    $certRows = ""
    if ($result.Error) {
        $certRows = "<tr class='cert-row error'><td colspan='7'>$($result.Error)</td></tr>"
    } elseif ($result.Certs -and $result.Certs.Count -gt 0) {
        foreach ($cert in $result.Certs) {
            $certCls  = switch ($cert.Status) { "EXPIRED" { "critical" } "WARN" { "warn" } default { "ok" } }
            $daysHtml = if ($null -ne $cert.DaysLeft) {
                if ($cert.DaysLeft -lt 0) { "<span class='badge critical'>EXPIRED $([math]::Abs($cert.DaysLeft))d ago</span>" }
                elseif ($cert.Status -eq "WARN") { "<span class='badge warn'>$($cert.DaysLeft) days</span>" }
                else { "<span class='badge ok'>$($cert.DaysLeft) days</span>" }
            } else { "<span class='badge'>?</span>" }

            $sansHtml = if ($cert.SANs -and $cert.SANs.Count -gt 0) {
                ($cert.SANs | ForEach-Object { "<span class='san'>$_</span>" }) -join " "
            } else { "<span class='muted'>none</span>" }

            $certRows += "
            <tr class='cert-row $certCls'>
              <td><code>$($cert.Alias)</code></td>
              <td class='small'>$($cert.Subject -replace 'CN=','' -replace ',.+','')</td>
              <td class='small muted'>$(if($cert.Issuer -match 'CN=([^,]+)'){$Matches[1]}else{$cert.Issuer})</td>
              <td>$($cert.NotAfter)</td>
              <td>$daysHtml</td>
              <td class='small'>$($cert.Algorithm)</td>
              <td class='small'>$sansHtml</td>
            </tr>"
        }
    } else {
        $certRows = "<tr class='cert-row warn'><td colspan='7'>No aliases found in keystore.</td></tr>"
    }

    $ksInfo = if ($result.KeystoreFile) {
        "<span class='muted'>$($result.KeystoreFile) [$($result.KeystoreType)]</span>"
    } else { "" }

    $svcInfo = if ($result.ServiceName) {
        "<span class='muted'> &nbsp;|&nbsp; Service: $($result.ServiceName)</span>"
    } else { "" }

    $tableRows += "
    <tr class='server-header $serverCls' onclick='toggle(""srv_$($result.ComputerName -replace '[^a-zA-Z0-9]','_')"")'>
      <td colspan='7'>
        &#x25BC; <strong>$($result.ComputerName)</strong>
        <span class='zone-tag'>$($result.GroupName)</span>
        <span class='status-badge $serverCls'>$($result.OverallStatus)</span>
        <br><small>$ksInfo$svcInfo</small>
      </td>
    </tr>
    <tbody id='srv_$($result.ComputerName -replace '[^a-zA-Z0-9]','_')' class='collapsible'>
      $certRows
    </tbody>"
}

$html = @"
<!DOCTYPE html>
<html><head><meta charset='UTF-8'>
<title>Tomcat Certificate Report - $timestamp</title>
<style>
  body{font-family:Consolas,monospace;background:#1e1e1e;color:#d4d4d4;margin:20px}
  h1{color:#4ec9b0} h2{color:#9cdcfe}
  table{border-collapse:collapse;width:100%;margin-top:16px}
  th{background:#2d2d2d;color:#9cdcfe;padding:8px 12px;text-align:left;border:1px solid #3c3c3c;font-size:12px}
  td{padding:6px 12px;border:1px solid #3c3c3c;font-size:12px;vertical-align:top}
  .server-header td{background:#1a3a5c;color:#9cdcfe;font-size:13px;cursor:pointer;padding:8px 14px}
  .server-header.warn td{background:#2a2800;border-left:4px solid #dcdcaa}
  .server-header.critical td{background:#2a1010;border-left:4px solid #f44747}
  .server-header.error td{background:#2a1010;border-left:4px solid #f44747}
  .server-header.ok td{border-left:4px solid #4ec9b0}
  .cert-row.ok td{color:#d4d4d4}
  .cert-row.warn td{background:#1e1a00;color:#dcdcaa}
  .cert-row.critical td{background:#1e0a0a;color:#f44747;font-weight:bold}
  .cert-row.error td{background:#1e0a0a;color:#f44747}
  tr:hover td{background:#252526}
  .collapsible{display:table-row-group}
  .badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold}
  .badge.ok{background:#1e3a2f;color:#4ec9b0;border:1px solid #4ec9b0}
  .badge.warn{background:#3a3000;color:#dcdcaa;border:1px solid #dcdcaa}
  .badge.critical{background:#3a1e1e;color:#f44747;border:1px solid #f44747}
  .san{display:inline-block;background:#252540;color:#c586c0;border-radius:4px;padding:1px 6px;margin:1px;font-size:10px}
  .zone-tag{display:inline-block;background:#1a3a5c;color:#9cdcfe;border-radius:4px;padding:1px 8px;margin-left:10px;font-size:11px}
  .status-badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:bold;margin-left:8px}
  .status-badge.ok{background:#1e3a2f;color:#4ec9b0}
  .status-badge.warn{background:#3a3000;color:#dcdcaa}
  .status-badge.critical,.status-badge.error{background:#3a1e1e;color:#f44747}
  .zone-pill{display:inline-block;margin:4px 6px;padding:6px 14px;border-radius:14px;font-size:13px;font-weight:bold}
  .zone-pill.ok{background:#1e3a2f;color:#4ec9b0;border:1px solid #4ec9b0}
  .zone-pill.warn{background:#3a3000;color:#dcdcaa;border:1px solid #dcdcaa}
  .zone-pill.critical{background:#3a1e1e;color:#f44747;border:1px solid #f44747}
  .summary{background:#252526;padding:12px;border-radius:6px;margin-bottom:18px}
  .muted{color:#6a9955;font-size:11px}
  .small{font-size:11px}
  code{background:#2d2d2d;padding:1px 5px;border-radius:3px;color:#ce9178}
</style></head><body>
<h1>&#x1F512; Tomcat Certificate Report</h1>
<div class='summary'>
  <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  &nbsp;|&nbsp; <strong>Servers:</strong> $serverCount
  &nbsp;|&nbsp; <strong>Warn threshold:</strong> $WarnDays days
</div>
<h2>Zone Summary</h2>
<div>$zoneRollupHtml</div>
<h2>Certificate Detail</h2>
<table>
<thead><tr>
  <th>Alias</th><th>Common Name</th><th>Issuer</th>
  <th>Expiry Date</th><th>Days Left</th><th>Algorithm</th><th>SANs</th>
</tr></thead>
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
Write-Log "" -Color White
Write-Log "HTML report : $htmlFile" -Color Green
Write-Log "Log         : $logFile"  -Color Green

# ============================================================
# OPTIONAL MANAGEMENT — pick a server and manage remotely
# ============================================================
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Remote Keystore Management" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Only offer servers that were reachable and have a keystore
$manageable = @($results | Where-Object { -not $_.Error -and $_.KeystoreFile })
if ($manageable.Count -eq 0) {
    Write-Host "  No manageable servers found (all errored or no keystore detected)." -ForegroundColor Yellow
    Write-Log "No manageable servers available for remote management." -Color Yellow
} else {
    Write-Host "  Servers available for remote management:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $manageable.Count; $i++) {
        $r      = $manageable[$i]
        $status = switch ($r.OverallStatus) { "CRITICAL" { "[CRITICAL]" } "WARN" { "[WARN]" } default { "[OK]" } }
        $color  = switch ($r.OverallStatus) { "CRITICAL" { "Red" } "WARN" { "Yellow" } default { "Green" } }
        Write-Host "  [$i] $($r.ComputerName)  ($($r.GroupName))  $status" -ForegroundColor $color
    }
    Write-Host "  [S] Skip management" -ForegroundColor Gray
    Write-Host ""

    $hasConsole2 = $true
    try { [void][System.Console]::KeyAvailable } catch { $hasConsole2 = $false }

    $mgmtChoice = ""
    if ($hasConsole2) {
        $mgmtChoice = (Read-Host "  Select server number or S to skip").Trim().ToUpper()
    } else {
        Write-Host "  Non-interactive mode — skipping management menu." -ForegroundColor Gray
        $mgmtChoice = "S"
    }

    if ($mgmtChoice -ne "S" -and $mgmtChoice -match "^\d+$") {
        $idx = [int]$mgmtChoice
        if ($idx -ge 0 -and $idx -lt $manageable.Count) {
            $target    = $manageable[$idx]
            $targetSrv = $target.ComputerName

            Write-Host ""
            Write-Host "  Managing: $targetSrv" -ForegroundColor Cyan
            Write-Host "  Keystore: $($target.KeystoreFile) [$($target.KeystoreType)]" -ForegroundColor White
            Write-Host ""
            Write-Host "  [U] Update / renew existing certificate (self-signed)"
            Write-Host "  [C] Create CSR for CA signing"
            Write-Host "  [I] Import CA-signed certificate"
            Write-Host "  [R] Rollback keystore from backup"
            Write-Host ""

            $action = (Read-Host "  Select action (U/C/I/R)").ToUpper()
            Write-Log "Remote management: $action on $targetSrv" -Color Cyan

            # ── Build the management scriptblock ─────────────────────────────
            # Pass the action and any needed params to the remote server
            # by invoking the existing keystore management script if present,
            # or running the management logic inline via Invoke-Command.

            $mgmtScriptBlock = {
                param(
                    [string]$Action,
                    [string]$KeystoreFile,
                    [string]$KeystoreType,
                    [string]$ServiceName,
                    [string]$TomcatBase,
                    [bool]  $WhatIf
                )

                # ── Re-derive keytool path ────────────────────────────────────
                function Find-Keytool {
                    $dacsJava = "E:\customers\shared\dacs\java"
                    if (Test-Path $dacsJava) {
                        $f = Get-ChildItem -Path $dacsJava -Recurse -Filter "keytool.exe" -ErrorAction SilentlyContinue |
                             Sort-Object LastWriteTime -Descending | Select-Object -First 1
                        if ($f) { return $f.FullName }
                    }
                    if ($env:JAVA_HOME) {
                        $p = Join-Path $env:JAVA_HOME "bin\keytool.exe"
                        if (Test-Path $p) { return $p }
                    }
                    $inPath = Get-Command keytool.exe -ErrorAction SilentlyContinue
                    if ($inPath) { return $inPath.Source }
                    foreach ($base in @(
                        "C:\Program Files\Java","C:\Program Files\Eclipse Adoptium",
                        "C:\Program Files\Microsoft","C:\Program Files\OpenJDK","C:\Program Files\Zulu"
                    )) {
                        $f = Get-ChildItem -Path $base -Recurse -Filter "keytool.exe" -ErrorAction SilentlyContinue |
                             Sort-Object LastWriteTime -Descending | Select-Object -First 1
                        if ($f) { return $f.FullName }
                    }
                    return $null
                }

                # ── Re-read keystore pass from server.xml ─────────────────────
                function Get-KeystorePass {
                    param([string]$TomcatBase, [string]$KeystoreFile)
                    $serverXml = Join-Path $TomcatBase "conf\server.xml"
                    if (-not (Test-Path $serverXml)) {
                        $found = Get-ChildItem -Path $TomcatBase -Recurse -Filter "server.xml" -ErrorAction SilentlyContinue |
                                 Select-Object -First 1
                        if ($found) { $serverXml = $found.FullName } else { return $null }
                    }
                    [xml]$xml = Get-Content $serverXml -ErrorAction Stop
                    $certElem = $xml.SelectNodes("//Certificate") | Select-Object -First 1
                    if ($certElem -and $certElem.certificateKeystorePassword) {
                        return $certElem.certificateKeystorePassword
                    }
                    $conn = $xml.SelectNodes("//Connector[@SSLEnabled='true']") | Select-Object -First 1
                    if ($conn -and $conn.keystorePass) { return $conn.keystorePass }
                    return $null
                }

                $keytool  = Find-Keytool
                $ksPass   = Get-KeystorePass -TomcatBase $TomcatBase -KeystoreFile $KeystoreFile
                $baseArgs = @("-keystore",$KeystoreFile,"-storetype",$KeystoreType,"-storepass",$ksPass)

                # ── List current aliases ──────────────────────────────────────
                $listOut = & $keytool -list -v @baseArgs 2>&1
                $aliases = ($listOut | Select-String "^Alias name:") -replace "Alias name:\s*",""

                return [PSCustomObject]@{
                    Keytool   = $keytool
                    KsPass    = $ksPass
                    BaseArgs  = $baseArgs
                    Aliases   = $aliases
                    ListOut   = $listOut -join "`n"
                    Action    = $Action
                }
            }

            $mgmtParams = @{
                ComputerName  = $targetSrv
                ErrorAction   = "Stop"
                ArgumentList  = $action, $target.KeystoreFile, $target.KeystoreType,
                                $target.ServiceName, $target.TomcatBase, [bool]$WhatIf
                ScriptBlock   = $mgmtScriptBlock
            }
            if ($Credential) { $mgmtParams["Credential"] = $Credential }

            try {
                $mgmtInfo = Invoke-Command @mgmtParams

                Write-Host ""
                Write-Host "  Remote server keytool  : $($mgmtInfo.Keytool)" -ForegroundColor Gray
                Write-Host "  Existing aliases       : $($mgmtInfo.Aliases -join ', ')" -ForegroundColor Gray
                Write-Host ""

                # ── Action-specific interactive prompts (run locally, execute remotely) ──
                switch ($action) {

                    'U' {
                        $aliasName = Read-Host "  Alias to update or create (e.g., tomcat)"
                        $dName     = Read-Host "  DN (e.g., CN=host.domain.com, OU=IT, O=MyOrg, C=US)"
                        $sanInput  = Read-Host "  SANs comma-separated (e.g., dns:host1,dns:host2) or blank"
                        $vInput    = Read-Host "  Validity days (default 397)"
                        $validDays = if ([string]::IsNullOrWhiteSpace($vInput)) { 397 } else { [math]::Min([int]$vInput,1095) }
                        $algChoice = (Read-Host "  Algorithm RSA/EC (default RSA)").ToUpper()
                        $szChoice  = if ($algChoice -ne "EC") { Read-Host "  RSA key size 2048/4096 (default 2048)" } else { "256" }

                        $algFinal  = if ($algChoice -eq "EC") { "EC" } else { "RSA" }
                        $szFinal   = if ($algChoice -eq "EC") { 256 } elseif ($szChoice -eq "4096") { 4096 } else { 2048 }

                        Write-Host ""
                        Write-Host "  ── Pending Action ──────────────────────" -ForegroundColor Yellow
                        Write-Host "  Server    : $targetSrv"
                        Write-Host "  Alias     : $aliasName"
                        Write-Host "  DN        : $dName"
                        Write-Host "  SANs      : $sanInput"
                        Write-Host "  Algorithm : $algFinal $szFinal"
                        Write-Host "  Validity  : $validDays days"
                        if ($WhatIf) { Write-Host "  [WHATIF] No changes will be made." -ForegroundColor Magenta }
                        Write-Host "  ────────────────────────────────────────" -ForegroundColor Yellow

                        $confirm = (Read-Host "  Proceed? (y/n)").ToLower()
                        if ($confirm -ne 'y') { Write-Log "Operation cancelled." -Color Yellow; break }

                        $renewScript = {
                            param($aliasName, $dName, $sanInput, $validDays, $algFinal, $szFinal,
                                  $KeystoreFile, $KeystoreType, $ServiceName, $TomcatBase, $WhatIf,
                                  $storagePath)

                            function Find-Keytool {
                                $dacsJava = "E:\customers\shared\dacs\java"
                                if (Test-Path $dacsJava) {
                                    $f = Get-ChildItem -Path $dacsJava -Recurse -Filter "keytool.exe" -ErrorAction SilentlyContinue |
                                         Sort-Object LastWriteTime -Descending | Select-Object -First 1
                                    if ($f) { return $f.FullName }
                                }
                                if ($env:JAVA_HOME) { $p = Join-Path $env:JAVA_HOME "bin\keytool.exe"; if (Test-Path $p) { return $p } }
                                $inPath = Get-Command keytool.exe -ErrorAction SilentlyContinue
                                if ($inPath) { return $inPath.Source }
                                foreach ($base in @("C:\Program Files\Java","C:\Program Files\Eclipse Adoptium","C:\Program Files\Microsoft","C:\Program Files\OpenJDK","C:\Program Files\Zulu")) {
                                    $f = Get-ChildItem -Path $base -Recurse -Filter "keytool.exe" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                                    if ($f) { return $f.FullName }
                                }
                                return $null
                            }

                            function Get-KsPass { param($TomcatBase)
                                $sx = Join-Path $TomcatBase "conf\server.xml"
                                if (-not (Test-Path $sx)) { $f = Get-ChildItem $TomcatBase -Recurse -Filter "server.xml" -ErrorAction SilentlyContinue | Select-Object -First 1; if ($f) { $sx = $f.FullName } else { return $null } }
                                [xml]$x = Get-Content $sx; $ce = $x.SelectNodes("//Certificate") | Select-Object -First 1
                                if ($ce -and $ce.certificateKeystorePassword) { return $ce.certificateKeystorePassword }
                                $co = $x.SelectNodes("//Connector[@SSLEnabled='true']") | Select-Object -First 1
                                if ($co -and $co.keystorePass) { return $co.keystorePass }
                                return $null
                            }

                            $keytool  = Find-Keytool
                            $ksPass   = Get-KsPass $TomcatBase
                            $baseArgs = @("-keystore",$KeystoreFile,"-storetype",$KeystoreType,"-storepass",$ksPass)
                            $log      = [System.Collections.Generic.List[string]]::new()

                            # Backup
                            if (-not $WhatIf -and (Test-Path $KeystoreFile)) {
                                $ts   = Get-Date -Format 'yyyyMMdd-HHmmss'
                                $dest = Join-Path $storagePath "$(Split-Path $KeystoreFile -Leaf).backup.$ts"
                                Copy-Item $KeystoreFile $dest -ErrorAction SilentlyContinue
                                $log.Add("Backed up to $dest")
                            }

                            # Delete existing alias
                            $existing = & $keytool -list @baseArgs -alias $aliasName 2>&1
                            if ($LASTEXITCODE -eq 0) {
                                if (-not $WhatIf) { & $keytool -delete -alias $aliasName @baseArgs 2>&1 | Out-Null }
                                $log.Add("Deleted existing alias '$aliasName'")
                            }

                            # Generate new keypair
                            $genArgs = @("-genkeypair","-alias",$aliasName,"-keyalg",$algFinal,"-keysize",$szFinal,
                                         "-validity",$validDays,"-dname",$dName) + $baseArgs
                            if (-not [string]::IsNullOrWhiteSpace($sanInput)) {
                                $sanArr  = $sanInput -split ",\s*"
                                $genArgs += "-ext"; $genArgs += "SAN=$($sanArr -join ',')"
                            }

                            if ($WhatIf) {
                                $log.Add("[WHATIF] Would run: keytool $($genArgs -join ' ')")
                                return [PSCustomObject]@{ Success = $true; Log = $log; ExitCode = 0 }
                            }

                            & $keytool $genArgs 2>&1 | ForEach-Object { $log.Add($_) }
                            $rc = $LASTEXITCODE
                            $log.Add($(if($rc -eq 0){"SUCCESS: keypair generated for '$aliasName'"}else{"FAILED: exit code $rc"}))
                            return [PSCustomObject]@{ Success = ($rc -eq 0); Log = $log; ExitCode = $rc }
                        }

                        $renewParams = @{
                            ComputerName = $targetSrv; ErrorAction = "Stop"
                            ArgumentList = $aliasName, $dName, $sanInput, $validDays, $algFinal, $szFinal,
                                           $target.KeystoreFile, $target.KeystoreType, $target.ServiceName,
                                           $target.TomcatBase, [bool]$WhatIf, $outputDir
                            ScriptBlock  = $renewScript
                        }
                        if ($Credential) { $renewParams["Credential"] = $Credential }
                        $renewResult = Invoke-Command @renewParams
                        foreach ($l in $renewResult.Log) { Write-Log "  $l" -Color (if($l -match "FAILED|ERROR"){"Red"}elseif($l -match "WHATIF"){"Magenta"}else{"Green"}) }

                        if ($renewResult.Success -and -not $WhatIf -and $target.ServiceName) {
                            $doRestart = (Read-Host "  Restart Tomcat service '$($target.ServiceName)' on $targetSrv now? (y/n)").ToLower()
                            if ($doRestart -eq 'y') {
                                $restartParams = @{
                                    ComputerName = $targetSrv; ErrorAction = "Stop"
                                    ArgumentList = $target.ServiceName
                                    ScriptBlock  = { param($svc) Restart-Service -Name $svc -Force -ErrorAction Stop }
                                }
                                if ($Credential) { $restartParams["Credential"] = $Credential }
                                try {
                                    Invoke-Command @restartParams
                                    Write-Log "  Service '$($target.ServiceName)' restarted on $targetSrv." -Color Green
                                } catch {
                                    Write-Log "  Failed to restart service: $_" -Color Red
                                }
                            }
                        }
                    }

                    'C' {
                        $aliasName = Read-Host "  Alias to generate CSR for"
                        $dName     = Read-Host "  DN (e.g., CN=host.domain.com, OU=IT, O=MyOrg, C=US)"
                        $sanInput  = Read-Host "  SANs comma-separated or blank"
                        Write-Log "CSR generation for alias '$aliasName' on $targetSrv initiated." -Color Cyan

                        $csrScript = {
                            param($aliasName, $dName, $sanInput, $KeystoreFile, $KeystoreType, $TomcatBase, $WhatIf)
                            function Find-Keytool {
                                $dacsJava = "E:\customers\shared\dacs\java"
                                if (Test-Path $dacsJava) { $f = Get-ChildItem $dacsJava -Recurse -Filter "keytool.exe" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($f) { return $f.FullName } }
                                if ($env:JAVA_HOME) { $p = Join-Path $env:JAVA_HOME "bin\keytool.exe"; if (Test-Path $p) { return $p } }
                                $ip = Get-Command keytool.exe -ErrorAction SilentlyContinue; if ($ip) { return $ip.Source }
                                foreach ($b in @("C:\Program Files\Java","C:\Program Files\Eclipse Adoptium","C:\Program Files\Microsoft","C:\Program Files\OpenJDK","C:\Program Files\Zulu")) { $f = Get-ChildItem $b -Recurse -Filter "keytool.exe" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($f) { return $f.FullName } }
                                return $null
                            }
                            function Get-KsPass { param($TomcatBase)
                                $sx = Join-Path $TomcatBase "conf\server.xml"; if (-not (Test-Path $sx)) { $f = Get-ChildItem $TomcatBase -Recurse -Filter "server.xml" -ErrorAction SilentlyContinue | Select-Object -First 1; if ($f) { $sx = $f.FullName } else { return $null } }
                                [xml]$x = Get-Content $sx; $ce = $x.SelectNodes("//Certificate") | Select-Object -First 1
                                if ($ce -and $ce.certificateKeystorePassword) { return $ce.certificateKeystorePassword }
                                $co = $x.SelectNodes("//Connector[@SSLEnabled='true']") | Select-Object -First 1; if ($co -and $co.keystorePass) { return $co.keystorePass }; return $null
                            }
                            $keytool  = Find-Keytool
                            $ksPass   = Get-KsPass $TomcatBase
                            $baseArgs = @("-keystore",$KeystoreFile,"-storetype",$KeystoreType,"-storepass",$ksPass)
                            $csrDir   = Split-Path $KeystoreFile -Parent
                            $csrFile  = Join-Path $csrDir "$aliasName-$(Get-Date -Format 'yyyyMMdd-HHmmss').csr"
                            $csrArgs  = @("-certreq","-alias",$aliasName,"-file",$csrFile) + $baseArgs
                            if (-not [string]::IsNullOrWhiteSpace($sanInput)) { $csrArgs += "-ext"; $csrArgs += "SAN=$($sanInput -replace '\s','')" }
                            $log = [System.Collections.Generic.List[string]]::new()
                            if ($WhatIf) { $log.Add("[WHATIF] Would run: keytool $($csrArgs -join ' ')"); return [PSCustomObject]@{ Success=$true; Log=$log; CsrFile=$csrFile } }
                            & $keytool $csrArgs 2>&1 | ForEach-Object { $log.Add($_) }
                            $rc = $LASTEXITCODE
                            $log.Add($(if($rc -eq 0){"CSR written to: $csrFile"}else{"FAILED: exit $rc"}))
                            return [PSCustomObject]@{ Success=($rc -eq 0); Log=$log; CsrFile=$csrFile }
                        }
                        $csrParams = @{ ComputerName=$targetSrv; ErrorAction="Stop"; ArgumentList=$aliasName,$dName,$sanInput,$target.KeystoreFile,$target.KeystoreType,$target.TomcatBase,[bool]$WhatIf; ScriptBlock=$csrScript }
                        if ($Credential) { $csrParams["Credential"] = $Credential }
                        $csrResult = Invoke-Command @csrParams
                        foreach ($l in $csrResult.Log) { Write-Log "  $l" -Color (if($l -match "FAILED|ERROR"){"Red"}elseif($l -match "WHATIF"){"Magenta"}else{"Green"}) }
                        if ($csrResult.Success) { Write-Log "  Submit $($csrResult.CsrFile) on $targetSrv to your CA, then use [I] to import." -Color Cyan }
                    }

                    'I' {
                        Write-Host "  NOTE: The certificate file must already exist on the remote server." -ForegroundColor Yellow
                        $aliasName = Read-Host "  Alias for signed cert"
                        $certFile  = Read-Host "  Full path to cert file on $targetSrv"
                        Write-Log "Importing CA-signed cert '$certFile' as alias '$aliasName' on $targetSrv." -Color Cyan

                        $importScript = {
                            param($aliasName, $certFile, $KeystoreFile, $KeystoreType, $TomcatBase, $WhatIf, $storagePath)
                            function Find-Keytool {
                                $dacsJava = "E:\customers\shared\dacs\java"
                                if (Test-Path $dacsJava) { $f = Get-ChildItem $dacsJava -Recurse -Filter "keytool.exe" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($f) { return $f.FullName } }
                                if ($env:JAVA_HOME) { $p = Join-Path $env:JAVA_HOME "bin\keytool.exe"; if (Test-Path $p) { return $p } }
                                $ip = Get-Command keytool.exe -ErrorAction SilentlyContinue; if ($ip) { return $ip.Source }
                                foreach ($b in @("C:\Program Files\Java","C:\Program Files\Eclipse Adoptium","C:\Program Files\Microsoft","C:\Program Files\OpenJDK","C:\Program Files\Zulu")) { $f = Get-ChildItem $b -Recurse -Filter "keytool.exe" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($f) { return $f.FullName } }
                                return $null
                            }
                            function Get-KsPass { param($TomcatBase)
                                $sx = Join-Path $TomcatBase "conf\server.xml"; if (-not (Test-Path $sx)) { $f = Get-ChildItem $TomcatBase -Recurse -Filter "server.xml" -ErrorAction SilentlyContinue | Select-Object -First 1; if ($f) { $sx = $f.FullName } else { return $null } }
                                [xml]$x = Get-Content $sx; $ce = $x.SelectNodes("//Certificate") | Select-Object -First 1
                                if ($ce -and $ce.certificateKeystorePassword) { return $ce.certificateKeystorePassword }
                                $co = $x.SelectNodes("//Connector[@SSLEnabled='true']") | Select-Object -First 1; if ($co -and $co.keystorePass) { return $co.keystorePass }; return $null
                            }
                            $keytool  = Find-Keytool
                            $ksPass   = Get-KsPass $TomcatBase
                            $baseArgs = @("-keystore",$KeystoreFile,"-storetype",$KeystoreType,"-storepass",$ksPass)
                            $log      = [System.Collections.Generic.List[string]]::new()
                            if (-not (Test-Path $certFile)) { $log.Add("ERROR: cert file not found: $certFile"); return [PSCustomObject]@{ Success=$false; Log=$log } }
                            if (-not $WhatIf -and (Test-Path $KeystoreFile)) {
                                $ts = Get-Date -Format 'yyyyMMdd-HHmmss'; $dest = Join-Path $storagePath "$(Split-Path $KeystoreFile -Leaf).backup.$ts"
                                Copy-Item $KeystoreFile $dest -ErrorAction SilentlyContinue; $log.Add("Backed up to $dest")
                            }
                            $impArgs = @("-importcert","-alias",$aliasName,"-file",$certFile,"-noprompt") + $baseArgs
                            if ($WhatIf) { $log.Add("[WHATIF] Would run: keytool $($impArgs -join ' ')"); return [PSCustomObject]@{ Success=$true; Log=$log } }
                            & $keytool $impArgs 2>&1 | ForEach-Object { $log.Add($_) }
                            $rc = $LASTEXITCODE; $log.Add($(if($rc -eq 0){"SUCCESS: imported '$aliasName'"}else{"FAILED: exit $rc"}))
                            return [PSCustomObject]@{ Success=($rc -eq 0); Log=$log }
                        }
                        $impParams = @{ ComputerName=$targetSrv; ErrorAction="Stop"; ArgumentList=$aliasName,$certFile,$target.KeystoreFile,$target.KeystoreType,$target.TomcatBase,[bool]$WhatIf,$outputDir; ScriptBlock=$importScript }
                        if ($Credential) { $impParams["Credential"] = $Credential }
                        $impResult = Invoke-Command @impParams
                        foreach ($l in $impResult.Log) { Write-Log "  $l" -Color (if($l -match "FAILED|ERROR"){"Red"}elseif($l -match "WHATIF"){"Magenta"}else{"Green"}) }

                        if ($impResult.Success -and -not $WhatIf -and $target.ServiceName) {
                            $doRestart = (Read-Host "  Restart Tomcat '$($target.ServiceName)' on $targetSrv? (y/n)").ToLower()
                            if ($doRestart -eq 'y') {
                                $rp = @{ ComputerName=$targetSrv; ErrorAction="Stop"; ArgumentList=$target.ServiceName; ScriptBlock={ param($s) Restart-Service -Name $s -Force -ErrorAction Stop } }
                                if ($Credential) { $rp["Credential"] = $Credential }
                                try { Invoke-Command @rp; Write-Log "  Service restarted." -Color Green }
                                catch { Write-Log "  Restart failed: $_" -Color Red }
                            }
                        }
                    }

                    'R' {
                        Write-Log "Rollback requested on $targetSrv." -Color Cyan
                        $rollbackScript = {
                            param($KeystoreFile, $KeystoreType, $ServiceName, $TomcatBase, $WhatIf, $storagePath)
                            $backupDir = $storagePath
                            if (-not (Test-Path $backupDir)) { return [PSCustomObject]@{ Success=$false; Log=@("No backup directory found at $backupDir"); Backups=@() } }
                            $backups = Get-ChildItem $backupDir -Filter "*.backup.*" | Sort-Object LastWriteTime -Descending
                            return [PSCustomObject]@{ Success=$true; Log=@(); Backups=($backups | Select-Object Name,FullName,LastWriteTime) }
                        }
                        $rbInfoParams = @{ ComputerName=$targetSrv; ErrorAction="Stop"; ArgumentList=$target.KeystoreFile,$target.KeystoreType,$target.ServiceName,$target.TomcatBase,[bool]$WhatIf,$outputDir; ScriptBlock=$rollbackScript }
                        if ($Credential) { $rbInfoParams["Credential"] = $Credential }
                        $rbInfo = Invoke-Command @rbInfoParams

                        if (-not $rbInfo.Success -or $rbInfo.Backups.Count -eq 0) {
                            Write-Log "  No backups found on $targetSrv in $outputDir." -Color Yellow
                        } else {
                            Write-Host ""
                            Write-Host "  Available backups on $targetSrv :" -ForegroundColor Cyan
                            for ($bi = 0; $bi -lt $rbInfo.Backups.Count; $bi++) {
                                Write-Host "  [$bi] $($rbInfo.Backups[$bi].Name)  ($($rbInfo.Backups[$bi].LastWriteTime))"
                            }
                            $sel = Read-Host "  Select backup number to restore"
                            if ($sel -match "^\d+$" -and [int]$sel -ge 0 -and [int]$sel -lt $rbInfo.Backups.Count) {
                                $chosenPath = $rbInfo.Backups[[int]$sel].FullName
                                $confirm    = (Read-Host "  Restore '$($rbInfo.Backups[[int]$sel].Name)' over '$($target.KeystoreFile)'? (y/n)").ToLower()
                                if ($confirm -eq 'y') {
                                    $doRbScript = {
                                        param($src, $dst, $svcName, $WhatIf)
                                        $log = [System.Collections.Generic.List[string]]::new()
                                        if ($WhatIf) { $log.Add("[WHATIF] Would copy $src to $dst"); return [PSCustomObject]@{ Success=$true; Log=$log } }
                                        Copy-Item -Path $src -Destination $dst -Force -ErrorAction Stop
                                        $log.Add("Restored $src to $dst")
                                        return [PSCustomObject]@{ Success=$true; Log=$log }
                                    }
                                    $doRbParams = @{ ComputerName=$targetSrv; ErrorAction="Stop"; ArgumentList=$chosenPath,$target.KeystoreFile,$target.ServiceName,[bool]$WhatIf; ScriptBlock=$doRbScript }
                                    if ($Credential) { $doRbParams["Credential"] = $Credential }
                                    $doRbResult = Invoke-Command @doRbParams
                                    foreach ($l in $doRbResult.Log) { Write-Log "  $l" -Color (if($l -match "FAILED|ERROR"){"Red"}elseif($l -match "WHATIF"){"Magenta"}else{"Green"}) }

                                    if ($doRbResult.Success -and -not $WhatIf -and $target.ServiceName) {
                                        $doRestart = (Read-Host "  Restart Tomcat '$($target.ServiceName)' on $targetSrv? (y/n)").ToLower()
                                        if ($doRestart -eq 'y') {
                                            $rp = @{ ComputerName=$targetSrv; ErrorAction="Stop"; ArgumentList=$target.ServiceName; ScriptBlock={ param($s) Restart-Service -Name $s -Force -ErrorAction Stop } }
                                            if ($Credential) { $rp["Credential"] = $Credential }
                                            try { Invoke-Command @rp; Write-Log "  Service restarted." -Color Green }
                                            catch { Write-Log "  Restart failed: $_" -Color Red }
                                        }
                                    }
                                } else { Write-Log "  Rollback cancelled." -Color Yellow }
                            } else { Write-Log "  Invalid selection." -Color Yellow }
                        }
                    }

                    default { Write-Log "  Invalid action: $action" -Color Yellow }
                }

            } catch {
                Write-Log "Remote management connection failed: $_" -Color Red
            }

        } else {
            Write-Log "Invalid server selection." -Color Yellow
        }
    } else {
        Write-Log "Management skipped." -Color Gray
    }
}

# ============================================================
# FOOTER
# ============================================================
Write-Log "" -Color White
Write-Log "========================================" -Color Cyan
Write-Log "Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Color Cyan
Write-Log "HTML : $htmlFile" -Color Green
Write-Log "Log  : $logFile"  -Color Green
Write-Log "========================================" -Color Cyan

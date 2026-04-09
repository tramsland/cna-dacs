#Requires -Version 5.1
#  [FW-09]  Unattended / scheduled execution in CAC environments.
#           A CAC must be physically present and PIN entered for interactive
#           runs. For scheduled tasks consider:
#             a) gMSA  — Windows manages the password; no credential needed.
#             b) Dedicated password-based service account with WinRM rights.
#           Document the chosen approach in a README alongside servers.txt.
#
# =============================================================================
# Remote Service Status Checker  —  ServiceCheck.ps1  v4.8
# =============================================================================
#
# CHANGES FROM v4.7
#   - BUGFIX: $tomcatVersion now populated from RELEASE-NOTES or catalina.jar
#             manifest under $tomcatHome instead of always returning "N/A".
#   - BUGFIX: Get-TermCountFromCache now accepts $TermEvents as an explicit
#             parameter instead of closing over the job-scope variable; all
#             call sites updated. Eliminates silent-zero risk if called before
#             $termEvents is assigned.
#   - BUGFIX: HtmlEncode substring truncation in $pfSb builder no longer throws
#             on strings shorter than 60 chars — length is checked first.
#   - BUGFIX: Temp files for GC log and CS log tailing are now removed in a
#             try/finally block so they are cleaned up even when an inner
#             function throws.
#   - BUGFIX: Stop-Job inside Invoke-InformantChecks now includes
#             -ErrorAction SilentlyContinue to prevent secondary errors if the
#             job has already exited.
#   - OPT:    Add-Type -AssemblyName System.Web moved to script top-level so
#             it is loaded once rather than on every HtmlEncode call.
#   - OPT:    Get-GcStats now calls Measure-Object once with both -Maximum and
#             -Average instead of two separate passes over $pauseTimes.
#   - OPT:    $eventLogCount promoted to a named param (-EventLogCount) so it
#             is user-configurable like all other thresholds.
#   - OPT:    Magic numbers (GC tail lines, WinRM timeouts, SC failure reset
#             interval, log truncation lengths, PF detail truncation) extracted
#             to named constants in the #region Constants block.
#   - STYLE:  Get-SvcUptimeFromProcs comment corrected — function does not use
#             $session; misleading reference removed.
#   - STYLE:  $termEvents scope dependency documented clearly at declaration
#             site inside job scriptblock.
#   - NOTE:   Invoke-InformantChecks still uses Start-Job internally (nested
#             jobs). Replacing with a runspace pool is the correct long-term
#             fix but is out of scope for this patch. A TODO comment marks the
#             location.
#
# BRACE DISCIPLINE
#   After any edit, verify brace balance:
#     (Get-Content .\ServiceCheck.ps1 | Select-String '\{').Count
#     (Get-Content .\ServiceCheck.ps1 | Select-String '\}').Count
#   Both numbers must match.
# =============================================================================

#region Parameters
param(
    [switch]$QuietOK,
    [string]$SmtpServer        = "smtp.domain.com",
    [int]$SmtpPort             = 25,
    [switch]$SmtpUseSsl,
    [System.Management.Automation.PSCredential]$SmtpCredential = $null,
    [string]$EmailFrom         = "monitoring@domain.com",
    [string]$EmailTo           = "ops@domain.com",
    [string]$TeamsWebhookUrl   = "",
    [switch]$AutoRestartStopped,
    # Credential parameter — for use with password-based service accounts only.
    # CAC (smart card) authenticated sessions do not use this parameter; the
    # script automatically uses the current Kerberos session token in that case.
    # If -Credential is passed in a CAC environment it will be ignored and a
    # warning will be displayed.
    [System.Management.Automation.PSCredential]$Credential     = $null,
    [int]$InformantWarnMs      = 5000,
    [int]$MaxParallelJobs      = 10,
    [int]$PreflightTimeoutMs   = 2000,
    [int]$LogTailLines         = 50,
    [int]$CertWarnDays         = 30,
    [int]$CertCritDays         = 7,
    [int]$GcPauseWarnMs        = 500,
    [int]$GcFreqWarnPerHour    = 20,
    [string]$CsLogRoot         = "E:\customers",
    [int]$EventLogCount        = 5,
    # #1  — HTTP vs HTTPS for Informant URLs
    [switch]$CsUseHttps,
    # #3  — WinRM retry on transient failures
    [int]$WinRmRetryCount      = 1,
    [int]$WinRmRetryDelaySec   = 10,
    # #5  — configurable drive thresholds
    [int]$DriveWarnPct         = 75,
    [int]$DriveCritPct         = 90,
    # #8  — configurable Informant component list
    [string[]]$InformantComponents = @("cs","db","adminservers","search","freespace","memoryspace","cpucheck"),
    # #10 — absolute free-space critical threshold (flags regardless of %)
    [int]$DriveCritFreeGB      = 10
)
#endregion Parameters

#region Constants
# Magic numbers extracted here so they are easy to tune without hunting through
# the script body. None of these are exposed as parameters because they are
# implementation details rather than operational thresholds, but they can be
# changed here if the environment requires it.

# Lines to fetch from catalina.out for GC analysis. Must be >= LogTailLines;
# the larger of the two is used at the call site.
$GcTailLines = 5000

# WinRM session timeouts in milliseconds.
$WinRmOpenTimeoutMs      = 30000
$WinRmOperationTimeoutMs = 60000

# SC.exe failure-recovery reset interval in seconds (24 hours).
$ScFailureResetSec = 86400

# SC.exe restart delay per action in milliseconds (60 seconds).
$ScRestartDelayMs = 60000

# Maximum characters kept from a single log line before truncation.
$LogLineTruncateChars = 300

# Maximum characters shown in pre-flight detail cells in the HTML report.
$PfDetailTruncateChars = 60
#endregion Constants

# =============================================================================
# FUTURE WORK — items deferred for a later version
# =============================================================================
#
#  [FW-01]  CSV / log / HTML file rotation (-KeepCsvDays param, default 30).
#           Without it the script directory fills up indefinitely on scheduled
#           runs. Pattern: Get-ChildItem | Where LastWriteTime -lt cutoff |
#           Remove-Item.
#
#  [FW-02]  Grand total line at bottom of zone rollup console output.
#           One-liner sum across $zoneSummary.Values.
#
#  [FW-03]  "Issues only" HTML toggle does not filter the pre-flight table.
#           Pre-flight rows use pf-ok/pf-warn/pf-crit CSS classes; the
#           em-only selector only targets ok/warn/crit. Extend toggleMode()
#           or exclude the pre-flight table from the toggle.
#
#  [FW-04]  -WhatIf / dry-run mode. Suppresses all state-changing calls
#           (sc.exe failure config, Invoke-AutoRestartRemote, email/Teams
#           alerts) and logs what would have happened. Important safety net
#           when using -AutoRestartStopped in an unfamiliar environment.
#
#  [FW-05]  Invoke-InformantChecks uses nested Start-Job (one process per
#           component per CS instance). Replace with a runspace pool,
#           consistent with the pre-flight parallel TCP checks.
#           Marked TODO (v4.9) in the job scriptblock.
#
#  [FW-06]  Log tail regex ($reErr in Get-LogTail) only covers generic
#           Java/log4j patterns. Add CS-specific strings: LLConnect, OTDS,
#           search engine, database connection, checkpoint.
#
#  [FW-07]  No JVM bitness check. A 32-bit JVM with large -Xmx silently
#           caps heap. Read JVM path from registry; check \x86\ vs \x64\.
#
#  [FW-08]  HTML auto-refresh for NOC/dashboard use. Add -HtmlRefreshSec
#           param (default 0 = off); inject <meta http-equiv="refresh">
#           when non-zero.
#
# =============================================================================

# PATCH v4.8: load System.Web once at script level rather than inside HtmlEncode
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Pre-flight helper — defined at script scope so it is available both in the
# pre-flight HTML builder and above the foreach loop (fixes lint issue where
# it was re-declared on every loop iteration).
# ---------------------------------------------------------------------------
function Truncate-PfDetail {
    param([string]$s, [int]$max)
    if (-not $s) { return "" }
    if ($s.Length -le $max) { return $s }
    return $s.Substring(0, $max)
}

#region Configuration
$configFile = Join-Path $PSScriptRoot "servers.txt"
if (-not (Test-Path $configFile)) {
    Write-Host "ERROR: Server config file not found: $configFile" -ForegroundColor Red
    Write-Host "Create servers.txt with one FQDN per line. [ZoneName] headers group servers." -ForegroundColor Yellow
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

$serverCount = ($serverGroups.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
if ($serverCount -eq 0) {
    Write-Host "ERROR: No servers found in $configFile" -ForegroundColor Red
    exit 1
}

$timestamp     = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile       = Join-Path $PSScriptRoot ("ServiceCheck_" + $timestamp + ".log")
$csvFile       = Join-Path $PSScriptRoot ("ServiceCheck_" + $timestamp + ".csv")
$htmlFile      = Join-Path $PSScriptRoot ("ServiceCheck_" + $timestamp + ".html")
$webTimeoutSec = 45
$jobTimeoutSec = 300
#endregion Configuration

#region Host-side helpers
function Write-Log {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
    Add-Content -Path $logFile -Value $Message -Encoding UTF8
}

function HtmlEncode {
    param([string]$s)
    if (-not $s) { return "" }
    # System.Web already loaded at script top — no Add-Type needed here
    try { return [System.Web.HttpUtility]::HtmlEncode($s) }
    catch {
        $s = $s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;")
        $s = $s.Replace('"',"&quot;").Replace("'","&#39;")
        return $s
    }
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

$StatusPriority = @{ "OK"=0; "WARN"=1; "CRITICAL"=2; "DOWN"=3 }
function Set-OverallStatus {
    param([string]$Current, [string]$New)
    if ($StatusPriority[$New] -gt $StatusPriority[$Current]) { return $New }
    return $Current
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
                version   = "1.2"
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
    } catch { Write-Log "Teams webhook failed: $_" -Color Red }
}
#endregion Host-side helpers

#region Pre-flight
function Test-TcpPort {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs)
    $tc = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $tc.BeginConnect($HostName, $Port, $null, $null)
        $ok = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok -and $tc.Connected) { $tc.EndConnect($ar); return $true }
        return $false
    } catch { return $false }
    finally { $tc.Close() }
}

function Test-WinRM {
    param([string]$ComputerName)
    try {
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                OS           = (Get-CimInstance Win32_OperatingSystem).Caption
            }
        } -ErrorAction Stop
        return @{ Ok = $true; Detail = "WinRM OK -- $($result.OS)" }
    } catch { return @{ Ok = $false; Detail = $_.Exception.Message } }
}

function Test-RemoteRegistry {
    param([string]$ComputerName)
    try {
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
                -Name "ProductName" -ErrorAction Stop
        } -ErrorAction Stop
        return @{ Ok = $true; Detail = "Registry OK -- OS: $result" }
    } catch { return @{ Ok = $false; Detail = $_.Exception.Message } }
}

function Test-InformantHttp {
    param([string]$ComputerName, [int]$TimeoutSec = 10)
    $portOk = Test-TcpPort -HostName $ComputerName -Port 80 -TimeoutMs ($TimeoutSec * 1000)
    if (-not $portOk) { return @{ Ok = $false; Detail = "TCP/80 closed or filtered" } }
    try {
        $resp = Invoke-WebRequest -Uri "http://$ComputerName/" -Method Head `
                    -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
        return @{ Ok = $true; Detail = "HTTP/80 responded -- status $($resp.StatusCode)" }
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $code = [int]$_.Exception.Response.StatusCode
            return @{ Ok = $true; Detail = "HTTP/80 up (status $code)" }
        }
        return @{ Ok = $false; Detail = "HTTP/80 open but request failed: $($_.Exception.Message)" }
    } catch { return @{ Ok = $false; Detail = "HTTP error: $($_.Exception.Message)" } }
}

function Test-WmiPerfCounter {
    param([string]$ComputerName)
    try {
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $cpu = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor `
                       -Filter "Name='_Total'" -ErrorAction Stop
            return $cpu.PercentProcessorTime
        } -ErrorAction Stop
        return @{ Ok = $true; Detail = "Perf counters OK -- CPU: $result%" }
    } catch { return @{ Ok = $false; Detail = "Perf counter failed: $($_.Exception.Message)" } }
}

$elevated  = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                 [Security.Principal.WindowsBuiltInRole]::Administrator)
$runningAs = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Detect CAC (smart card) authentication — the identity token will show an
# issuer chain rooted in a DoD/CAC CA when smart card logon is in use.
# In that case -Credential is meaningless and must be suppressed.
$authType  = [System.Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
$isCacSession = $authType -match 'Kerberos' -and (
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Claims |
    Where-Object { $_.Type -eq 'http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod' -and
                   $_.Value -match 'smartcard|certificate' }
)

if ($Credential -and $isCacSession) {
    Write-Host ""
    Write-Host "  WARNING: -Credential was supplied but this session is CAC-authenticated." -ForegroundColor Yellow
    Write-Host "           Smart card authentication uses the current Kerberos token —" -ForegroundColor Yellow
    Write-Host "           the -Credential parameter will be ignored." -ForegroundColor Yellow
    Write-Host "           For unattended runs in a CAC environment, use a gMSA or" -ForegroundColor Yellow
    Write-Host "           a dedicated password-based service account instead." -ForegroundColor Yellow
    Write-Host ""
    $Credential = $null
}

if (-not $Credential -and -not $isCacSession) {
    Write-Host "  INFO: Running as current user ($runningAs) with no explicit credential." -ForegroundColor Gray
    Write-Host "        Ensure this account has WinRM rights on all target servers." -ForegroundColor Gray
    Write-Host ""
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  SERVICE CHECK v4.8 -- CONNECTION PRE-FLIGHT (WinRM)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Running as : $runningAs" -ForegroundColor $(if ($elevated) { "Green" } else { "Red" })
Write-Host "  Elevated   : $(if ($elevated) { 'YES' } else { 'NO -- some operations may fail' })" `
    -ForegroundColor $(if ($elevated) { "Green" } else { "Yellow" })
Write-Host "  Transport  : WinRM/PSRemoting (port 5985)" -ForegroundColor Gray
Write-Host "  Servers    : $serverCount from servers.txt" -ForegroundColor Gray
Write-Host "  Timeout    : ${PreflightTimeoutMs}ms per TCP check" -ForegroundColor Gray
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

$pfServers = $serverGroups.Values | ForEach-Object { $_ } | Sort-Object -Unique
$pfResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$pfTotal   = @($pfServers).Count

$pfPool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, [math]::Min($pfTotal, 20))
$pfPool.Open()

$pfScriptBlock = {
    param($server, $timeoutMs)
    function Test-TcpPortLocal {
        param([string]$H, [int]$P, [int]$T)
        $tc = New-Object System.Net.Sockets.TcpClient
        try {
            $ar = $tc.BeginConnect($H, $P, $null, $null)
            $ok = $ar.AsyncWaitHandle.WaitOne($T, $false)
            if ($ok -and $tc.Connected) { $tc.EndConnect($ar); return $true }
            return $false
        } catch { return $false }
        finally { $tc.Close() }
    }
    $icmp    = Test-Connection -ComputerName $server -Count 2 -Quiet -ErrorAction SilentlyContinue
    $icmpMs  = $null
    if ($icmp) {
        $ping   = Test-Connection -ComputerName $server -Count 1 -ErrorAction SilentlyContinue
        $icmpMs = if ($ping) { $ping.ResponseTime } else { $null }
    }
    [PSCustomObject]@{
        Server  = $server
        Icmp    = $icmp
        IcmpMs  = $icmpMs
        Tcp5985 = Test-TcpPortLocal $server 5985 $timeoutMs
        Tcp5986 = Test-TcpPortLocal $server 5986 $timeoutMs
        Tcp445  = Test-TcpPortLocal $server 445  $timeoutMs
        Tcp80   = Test-TcpPortLocal $server 80   $timeoutMs
        Tcp443  = Test-TcpPortLocal $server 443  $timeoutMs
        Tcp8080 = Test-TcpPortLocal $server 8080 $timeoutMs
        Tcp8443 = Test-TcpPortLocal $server 8443 $timeoutMs
    }
}

$pfRunspaces = foreach ($server in $pfServers) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pfPool
    [void]$ps.AddScript($pfScriptBlock).AddArgument($server).AddArgument($PreflightTimeoutMs)
    [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Server = $server }
}

Write-Host "  Running parallel pre-flight TCP checks ..." -ForegroundColor Gray

foreach ($rs in $pfRunspaces) {
    $tcpData = $rs.PS.EndInvoke($rs.Handle)
    $rs.PS.Dispose()

    $winrmResult = if ($tcpData.Tcp5985) { Test-WinRM          -ComputerName $rs.Server } else { @{ Ok=$false; Detail="Skipped -- TCP/5985 closed" } }
    $regResult   = if ($winrmResult.Ok)  { Test-RemoteRegistry -ComputerName $rs.Server } else { @{ Ok=$false; Detail="Skipped -- WinRM failed" } }
    $httpResult  = if ($tcpData.Tcp80)   { Test-InformantHttp  -ComputerName $rs.Server } else { @{ Ok=$false; Detail="TCP/80 closed" } }
    $perfResult  = if ($winrmResult.Ok)  { Test-WmiPerfCounter -ComputerName $rs.Server } else { @{ Ok=$false; Detail="Skipped -- WinRM failed" } }

    $diagnosis = [System.Collections.Generic.List[string]]::new()
    if (-not $tcpData.Icmp)                              { $diagnosis.Add("HOST UNREACHABLE -- check DNS, network path, firewall") }
    if ($tcpData.Icmp -and -not $tcpData.Tcp5985)        { $diagnosis.Add("TCP/5985 blocked -- run: winrm quickconfig on target") }
    if ($tcpData.Tcp5985 -and -not $winrmResult.Ok)      { $diagnosis.Add("WinRM port open but session failed") }
    if ($winrmResult.Ok -and -not $regResult.Ok)         { $diagnosis.Add("Registry access failed") }
    if ($tcpData.Icmp -and -not $tcpData.Tcp80)         { $diagnosis.Add("TCP/80 closed -- Informant checks will fail") }
    if ($winrmResult.Ok -and -not $perfResult.Ok)        { $diagnosis.Add("WMI perf counters unavailable -- CPU will show N/A") }
    if (-not $elevated)                                  { $diagnosis.Add("NOT ELEVATED -- some operations may fail") }

    $overallOk = $tcpData.Icmp -and $tcpData.Tcp5985 -and $winrmResult.Ok
    $pfResults.Add([PSCustomObject]@{
        Server      = $rs.Server
        Ping        = $tcpData.Icmp;    PingMs      = $tcpData.IcmpMs
        TCP5985     = $tcpData.Tcp5985; TCP5986     = $tcpData.Tcp5986
        TCP445      = $tcpData.Tcp445;  TCP80       = $tcpData.Tcp80
        TCP443      = $tcpData.Tcp443;  TCP8080     = $tcpData.Tcp8080
        TCP8443     = $tcpData.Tcp8443
        WinRM       = $winrmResult.Ok;  WinRMDetail = $winrmResult.Detail
        RegProv     = $regResult.Ok;    RegDetail   = $regResult.Detail
        Http        = $httpResult.Ok;   HttpDetail  = $httpResult.Detail
        PerfCounter = $perfResult.Ok;   PerfDetail  = $perfResult.Detail
        Diagnosis   = $diagnosis;       OverallOk   = $overallOk
    })

    $dot      = if ($overallOk) { " READY" } elseif ($tcpData.Icmp) { " PARTIAL" } else { " UNREACHABLE" }
    $dotColor = if ($overallOk) { "Green" }  elseif ($tcpData.Icmp) { "Yellow" }   else { "Red" }
    Write-Host "  $($rs.Server) ...$dot" -ForegroundColor $dotColor
}
$pfPool.Close()
$pfPool.Dispose()

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  PRE-FLIGHT DETAIL" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

foreach ($r in ($pfResults | Sort-Object { if ($_.OverallOk) { 1 } else { 0 } })) {
    $hdrColor = if ($r.OverallOk) { "Green" } elseif ($r.Ping) { "Yellow" } else { "Red" }
    $status   = if ($r.OverallOk) { "READY" } elseif ($r.Ping) { "PARTIAL" } else { "UNREACHABLE" }
    Write-Host ""
    Write-Host "  -- $($r.Server)  [$status] --" -ForegroundColor $hdrColor

    $checks = @(
        @{ Label="ICMP Ping";          Ok=$r.Ping;        Required="Required";          Detail=if ($r.PingMs) { "$($r.PingMs)ms" } else { "No response" } }
        @{ Label="TCP/5985 WinRM";     Ok=$r.TCP5985;     Required="Required";          Detail="WinRM HTTP transport" }
        @{ Label="TCP/5986 WinRM-S";   Ok=$r.TCP5986;     Required="Optional";          Detail="WinRM HTTPS transport" }
        @{ Label="TCP/445  SMB";       Ok=$r.TCP445;      Required="Optional";          Detail="SMB/file access" }
        @{ Label="TCP/80   HTTP";      Ok=$r.TCP80;       Required="Required for CS";   Detail="Informant / CS web" }
        @{ Label="TCP/443  HTTPS";     Ok=$r.TCP443;      Required="For cert check";    Detail="TLS certificate inspection" }
        @{ Label="TCP/8080 HTTP-alt";  Ok=$r.TCP8080;     Required="Optional";          Detail="Tomcat alternate port" }
        @{ Label="TCP/8443 HTTPS-alt"; Ok=$r.TCP8443;     Required="Optional";          Detail="Tomcat TLS alternate port" }
        @{ Label="WinRM Session";      Ok=$r.WinRM;       Required="Required";          Detail=$r.WinRMDetail }
        @{ Label="Registry Access";    Ok=$r.RegProv;     Required="Required JVM info"; Detail=$r.RegDetail }
        @{ Label="HTTP Informant";     Ok=$r.Http;        Required="Required for CS";   Detail=$r.HttpDetail }
        @{ Label="WMI Perf Counters";  Ok=$r.PerfCounter; Required="Recommended CPU%";  Detail=$r.PerfDetail }
    )
    foreach ($chk in $checks) {
        $icon  = if ($chk.Ok) { "[OK]  " } else { "[FAIL]" }
        $color = if ($chk.Ok) { "Green" }  else { "Red" }
        Write-Host ("    {0}  {1,-26} [{2,-22}]  {3}" -f $icon, $chk.Label, $chk.Required, $chk.Detail) -ForegroundColor $color
    }
    if ($r.Diagnosis.Count -gt 0) {
        Write-Host ""
        Write-Host "    DIAGNOSIS:" -ForegroundColor Yellow
        foreach ($d in $r.Diagnosis) { Write-Host "      >> $d" -ForegroundColor Yellow }
    }
}

$pfReady   = ($pfResults | Where-Object { $_.OverallOk }).Count
$pfPartial = ($pfResults | Where-Object { $_.Ping -and -not $_.OverallOk }).Count
$pfDown    = ($pfResults | Where-Object { -not $_.Ping }).Count

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
$sumColor = if ($pfDown -gt 0 -or $pfPartial -gt 0) { "Yellow" } else { "Green" }
Write-Host ("  SUMMARY: {0} ready   {1} partial   {2} unreachable   (of {3})" -f `
    $pfReady, $pfPartial, $pfDown, $pfTotal) -ForegroundColor $sumColor
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

if ($pfReady -lt $pfTotal) {
    Write-Host "  Some servers have connection issues (see DIAGNOSIS above)." -ForegroundColor Yellow
    Write-Host "  The main check will still attempt all servers and report failures normally." -ForegroundColor Yellow
    Write-Host ""
}

$answer = Read-Host "  Continue with service checks? [Y/N]"
if ($answer -notmatch '^[Yy]') { Write-Host "  Aborted." -ForegroundColor Gray; exit 0 }
Write-Host ""

# ---------------------------------------------------------------------------
# Environment validation — probes one server per zone to verify service
# discovery assumptions before committing to the full parallel run.
# Warnings here do not abort the run; they highlight config issues early.
# Covers pre-test suggestions #5 (CS service description), #6 (log path),
# and #7 (Tomcat service discovery).
# ---------------------------------------------------------------------------
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  ENVIRONMENT VALIDATION (one server per zone)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

foreach ($group in $serverGroups.Keys) {
    $probe = $serverGroups[$group] | Select-Object -First 1
    if (-not $probe) { continue }

    $pfEntry = $pfResults | Where-Object { $_.Server -eq $probe } | Select-Object -First 1
    if (-not $pfEntry -or -not $pfEntry.OverallOk) {
        Write-Host "  [$group] $probe — skipped (WinRM not ready)" -ForegroundColor Gray
        continue
    }

    Write-Host "  [$group] probing $probe ..." -ForegroundColor Gray

    try {
        $valResult = Invoke-Command -ComputerName $probe -ErrorAction Stop -ScriptBlock {
            param($csLogRoot)
            $svcs = Get-CimInstance Win32_Service

            # Check #5 — CS service description match
            $csSvcs = @($svcs | Where-Object {
                $_.Description -like "*Content Server*" -and
                $_.Description -notlike "*Content Server Admin*"
            })
            # Check #7 — Tomcat discovery (description/name and fallback PathName)
            $tomcatByName = $svcs | Where-Object {
                $_.DisplayName -like "*Apache*Tomcat*" -or $_.Name -like "*Tomcat*"
            } | Select-Object -First 1
            $tomcatByPath = if (-not $tomcatByName) {
                $svcs | Where-Object {
                    $_.PathName -like "*tomcat*" -or $_.PathName -like "*catalina*"
                } | Select-Object -First 1
            } else { $null }

            # Check #6 — CS log path existence
            $logPathResults = foreach ($cs in $csSvcs) {
                $logDir = "$csLogRoot\$($cs.Name)\dacs\contentserver_logs\thread_logs"
                [PSCustomObject]@{
                    ServiceName = $cs.Name
                    LogPath     = $logDir
                    Exists      = (Test-Path $logDir)
                }
            }

            [PSCustomObject]@{
                CsServices     = $csSvcs | Select-Object Name, DisplayName, Description
                TomcatByName   = $tomcatByName | Select-Object Name, DisplayName
                TomcatByPath   = $tomcatByPath | Select-Object Name, DisplayName, PathName
                LogPathResults = $logPathResults
            }
        } -ArgumentList $CsLogRoot

        # Report CS service discovery (#5)
        if ($valResult.CsServices -and @($valResult.CsServices).Count -gt 0) {
            foreach ($cs in @($valResult.CsServices)) {
                Write-Host ("    [OK]   CS service found : {0} ({1})" -f $cs.Name, $cs.DisplayName) -ForegroundColor Green
            }
        } else {
            Write-Host "    [WARN] No CS services found via Description match — check service descriptions on $probe" -ForegroundColor Yellow
            Write-Host "           Consider adjusting the service filter in the script if services use non-standard descriptions." -ForegroundColor Yellow
        }

        # Report Tomcat discovery (#7)
        if ($valResult.TomcatByName) {
            Write-Host ("    [OK]   Tomcat found by name/display : {0}" -f $valResult.TomcatByName.Name) -ForegroundColor Green
        } elseif ($valResult.TomcatByPath) {
            Write-Host ("    [WARN] Tomcat not found by name — found by PathName : {0} ({1})" -f `
                $valResult.TomcatByPath.Name, $valResult.TomcatByPath.PathName) -ForegroundColor Yellow
            Write-Host "           Add Name '$($valResult.TomcatByPath.Name)' to the Tomcat service filter or rename the service." -ForegroundColor Yellow
        } else {
            Write-Host "    [WARN] No Tomcat service found by name or PathName on $probe" -ForegroundColor Yellow
        }

        # Report CS log paths (#6)
        if ($valResult.LogPathResults) {
            foreach ($lp in @($valResult.LogPathResults)) {
                if ($lp.Exists) {
                    Write-Host ("    [OK]   Log path exists : {0}" -f $lp.LogPath) -ForegroundColor Green
                } else {
                    Write-Host ("    [WARN] Log path missing : {0}" -f $lp.LogPath) -ForegroundColor Yellow
                    Write-Host "           Use -CsLogRoot to override the log root if logs are on a different drive/path." -ForegroundColor Yellow
                }
            }
        }

    } catch {
        Write-Host "    [FAIL] Validation probe failed on $probe : $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# Build pre-flight HTML section
$pfSb = [System.Text.StringBuilder]::new()
foreach ($r in ($pfResults | Sort-Object Server)) {
    $rowStatus   = if ($r.OverallOk) { "ok" } elseif ($r.Ping) { "warn" } else { "crit" }
    $statusLabel = if ($r.OverallOk) { "READY" } elseif ($r.Ping) { "PARTIAL" } else { "UNREACHABLE" }
    [void]$pfSb.Append("<tr class='pf-$rowStatus'>")
    [void]$pfSb.Append("<td class='pf-server'>$(HtmlEncode $r.Server)</td>")
    [void]$pfSb.Append("<td><span class='chip $rowStatus'>$statusLabel</span></td>")

    # PATCH v4.9: safe truncation helper moved to script scope (was re-declared
    # on every loop iteration inside foreach — see top of script).
    $pfChecks = @(
        @{ Ok=$r.Ping;        Detail=if ($r.PingMs) { "$($r.PingMs)ms" } else { "No response" } }
        @{ Ok=$r.TCP5985;     Detail="WinRM" }
        @{ Ok=$r.TCP443;      Detail="HTTPS" }
        @{ Ok=$r.TCP8443;     Detail="Tomcat TLS" }
        @{ Ok=$r.TCP80;       Detail="HTTP" }
        @{ Ok=$r.WinRM;       Detail=if ($r.WinRM) { "OK" } else { Truncate-PfDetail $r.WinRMDetail $PfDetailTruncateChars } }
        @{ Ok=$r.RegProv;     Detail=if ($r.RegProv) { "OK" } else { Truncate-PfDetail $r.RegDetail $PfDetailTruncateChars } }
        @{ Ok=$r.PerfCounter; Detail=if ($r.PerfCounter) { "OK" } else { "N/A" } }
    )
    foreach ($chk in $pfChecks) {
        $cls  = if ($chk.Ok) { "pf-ok" } else { "pf-fail" }
        $icon = if ($chk.Ok) { "OK" }    else { "FAIL" }
        [void]$pfSb.Append("<td class='$cls' title='$(HtmlEncode $chk.Detail)'>$icon</td>")
    }
    if ($r.Diagnosis.Count -gt 0) {
        $items = ($r.Diagnosis | ForEach-Object { "<li>$(HtmlEncode $_)</li>" }) -join ""
        [void]$pfSb.Append("<td class='pf-diag-cell'><ul class='pf-diag'>$items</ul></td>")
    } else {
        [void]$pfSb.Append("<td></td>")
    }
    [void]$pfSb.Append("</tr>")
}

$pfHtmlSection = @"
<div class='pf-section'>
  <div class='pf-title'>Connection pre-flight results (WinRM)</div>
  <div class='pf-meta'>Run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Running as: $(HtmlEncode $runningAs) | Elevated: $(if ($elevated) {'YES'} else {'NO'})</div>
  <table class='pf-tbl'>
    <thead><tr>
      <th>Server</th><th>Status</th><th>Ping</th><th>TCP/5985</th><th>TCP/443</th>
      <th>TCP/8443</th><th>TCP/80</th><th>WinRM</th><th>Registry</th><th>PerfCtr</th><th>Diagnosis</th>
    </tr></thead>
    <tbody>$($pfSb.ToString())</tbody>
  </table>
</div>
"@
#endregion Pre-flight

#region Job scriptblock
$checkServicesScript = {
    param(
        [string]$ComputerName,
        [string]$GroupName,
        [int]$WebTimeoutSec,
        [int]$InformantWarnMs,
        [int]$EventLogCount,
        [bool]$AutoRestartStopped,
        [int]$LogTailLines,
        [int]$CertWarnDays,
        [int]$CertCritDays,
        [int]$GcPauseWarnMs,
        [int]$GcFreqWarnPerHour,
        [string]$CsLogRoot,
# PATCH v4.9: constants passed in so job has no magic numbers
        [int]$GcTailLines,
        [int]$WinRmOpenTimeoutMs,
        [int]$WinRmOperationTimeoutMs,
        [int]$ScFailureResetSec,
        [int]$ScRestartDelayMs,
        [int]$LogLineTruncateChars,
        # #1  Informant scheme
        [bool]$CsUseHttps,
        # #3  WinRM retry
        [int]$WinRmRetryCount,
        [int]$WinRmRetryDelaySec,
        # #5  drive thresholds
        [int]$DriveWarnPct,
        [int]$DriveCritPct,
        # #8  Informant components
        [string[]]$InformantComponents,
        # #10 absolute free-space threshold
        [int]$DriveCritFreeGB
    )

    #region Job inline helpers
    # Defensive cast: ensures $InformantComponents is always a proper array
    # even if a single string was passed and serialized as a scalar by Start-Job.
    $InformantComponents = @($InformantComponents) | Where-Object { $_ }
    function Get-VisualBar {
        param([double]$Pct, [int]$W = 20)
        $f = [math]::Round($Pct / (100 / $W))
        return ("[" + ("#" * $f).PadRight($W, "-") + "]")
    }

    function Get-ThresholdTag {
        param([double]$Pct)
        if ($Pct -ge 90) { return " [CRITICAL]" }
        elseif ($Pct -ge 75) { return " [WARN]" }
        return ""
    }

    $StatusPriority = @{ "OK"=0; "WARN"=1; "CRITICAL"=2; "DOWN"=3 }
    function Set-OverallStatus {
        param([string]$Current, [string]$New)
        if ($StatusPriority[$New] -gt $StatusPriority[$Current]) { return $New }
        return $Current
    }

    # TODO (v4.9): replace nested Start-Job calls with a runspace pool to avoid
    # per-request process overhead and improve reliability under load.
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
                    [PSCustomObject]@{ Content=$r.Content.Trim(); Ms=$sw.ElapsedMilliseconds; Error=$null }
                } catch {
                    $sw.Stop()
                    [PSCustomObject]@{ Content=$null; Ms=$sw.ElapsedMilliseconds; Error=$_.Exception.Message }
                }
            } -ArgumentList $uri, $TimeoutSec
        }
        $results = [hashtable]::new()
        foreach ($comp in $jobs.Keys) {
            $j = $jobs[$comp] | Wait-Job -Timeout ($TimeoutSec + 15)
            if ($j) {
                $results[$comp] = Receive-Job -Job $jobs[$comp]
                Remove-Job -Job $jobs[$comp] -Force
            } else {
                # PATCH v4.8: -ErrorAction SilentlyContinue prevents secondary
                # error if job exited between Wait-Job timeout and Stop-Job call
                Stop-Job   -Job $jobs[$comp] -ErrorAction SilentlyContinue
                Remove-Job -Job $jobs[$comp] -Force
                $results[$comp] = [PSCustomObject]@{ Content=$null; Ms=($TimeoutSec*1000); Error="Timed out" }
            }
        }
        return $results
    }

    function Get-TlsCertInfo {
        param([string]$HostName, [int[]]$Ports, [int]$TimeoutMs = 5000)
        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($port in $Ports) {
            $tcpClient = $null
            $sslStream = $null
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $ar = $tcpClient.BeginConnect($HostName, $port, $null, $null)
                $ok = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
                if (-not $ok -or -not $tcpClient.Connected) { continue }
                $callback  = [System.Net.Security.RemoteCertificateValidationCallback]{ $true }
                $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, $callback)
                $sslStream.AuthenticateAsClient($HostName)
                $cert2    = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $sslStream.RemoteCertificate
                $daysLeft = [math]::Floor(($cert2.NotAfter - (Get-Date)).TotalDays)
                $results.Add([PSCustomObject]@{
                    Port       = $port
                    Subject    = $cert2.Subject
                    Issuer     = $cert2.Issuer
                    Expiry     = $cert2.NotAfter.ToString("yyyy-MM-dd")
                    DaysLeft   = $daysLeft
                    Thumbprint = $cert2.Thumbprint
                    Error      = $null
                })
            } catch {
                $results.Add([PSCustomObject]@{
                    Port=($port); Subject=""; Issuer=""; Expiry=""; DaysLeft=$null
                    Thumbprint=""; Error=$_.Exception.Message
                })
            } finally {
                if ($sslStream) { try { $sslStream.Close() } catch {} }
                if ($tcpClient) { try { $tcpClient.Close() } catch {} }
            }
        }
        return $results
    }

    function Get-GcStats {
        param([string]$LogPath, [int]$LookbackHours = 1)
        $result = [PSCustomObject]@{
            Events       = [System.Collections.Generic.List[PSCustomObject]]::new()
            MaxPauseMs   = 0
            AvgPauseMs   = 0
            CountPerHour = 0
            OomFound     = $false
            HeapTrendMB  = $null
            ParseError   = $null
        }
        if (-not (Test-Path $LogPath)) { $result.ParseError = "Log not found: $LogPath"; return $result }
        try {
            $cutoff  = (Get-Date).AddHours(-$LookbackHours)
            $lines   = Get-Content $LogPath -Tail 5000 -ErrorAction Stop

            $re9   = [regex]'^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+[^\]]*\]\[.*?\]\[gc\].*?Pause\s+(\w+).*?(\d+)M->(\d+)M\((\d+)M\)\s+([\d.]+)ms'
            $re8   = [regex]'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*?\[(\w+)[^\]]*\].*?(\d+)M->(\d+)M\((\d+)M\),?\s+([\d.]+)\s+secs'
            $reOom = [regex]'OutOfMemoryError'

            $pauseTimes    = [System.Collections.Generic.List[double]]::new()
            $heapAfterList = [System.Collections.Generic.List[int]]::new()

            foreach ($line in $lines) {
                if ($reOom.IsMatch($line)) { $result.OomFound = $true }

                $m9 = $re9.Match($line)
                $m8 = $re8.Match($line)

                $ts          = $null
                $type        = ""
                $heapAfterMB = 0
                $heapMaxMB   = 0
                $pauseMs     = 0.0
                $matched     = $false

                if ($m9.Success) {
                    try { $ts = [datetime]::Parse($m9.Groups[1].Value) } catch { continue }
                    $type        = $m9.Groups[2].Value
                    $heapAfterMB = [int]$m9.Groups[4].Value
                    $heapMaxMB   = [int]$m9.Groups[5].Value
                    $pauseMs     = [double]$m9.Groups[6].Value
                    $matched     = $true
                } elseif ($m8.Success) {
                    try { $ts = [datetime]::Parse($m8.Groups[1].Value) } catch { continue }
                    $type        = $m8.Groups[2].Value
                    $heapAfterMB = [int]$m8.Groups[4].Value
                    $heapMaxMB   = [int]$m8.Groups[5].Value
                    $pauseMs     = [double]$m8.Groups[6].Value * 1000
                    $matched     = $true
                }

                if ($matched -and $ts -ge $cutoff) {
                    $result.Events.Add([PSCustomObject]@{
                        Timestamp   = $ts.ToString("yyyy-MM-dd HH:mm:ss")
                        Type        = $type
                        HeapAfterMB = $heapAfterMB
                        HeapMaxMB   = $heapMaxMB
                        PauseMs     = [math]::Round($pauseMs, 1)
                    })
                    $pauseTimes.Add($pauseMs)
                    $heapAfterList.Add($heapAfterMB)
                }
            }

            if ($pauseTimes.Count -gt 0) {
                # PATCH v4.8: single Measure-Object call for both Maximum and Average
                $stats               = $pauseTimes | Measure-Object -Maximum -Average
                $result.MaxPauseMs   = [math]::Round($stats.Maximum, 1)
                $result.AvgPauseMs   = [math]::Round($stats.Average, 1)
                $result.CountPerHour = $result.Events.Count
            }
            if ($heapAfterList.Count -ge 4) {
                $firstAvg = ($heapAfterList | Select-Object -First 3 | Measure-Object -Average).Average
                $lastAvg  = ($heapAfterList | Select-Object -Last  3 | Measure-Object -Average).Average
                $result.HeapTrendMB = [math]::Round($lastAvg - $firstAvg, 0)
            }
        } catch { $result.ParseError = $_.Exception.Message }
        return $result
    }

    function Get-LogTail {
        param([string]$LogPath, [int]$TailLines, [string]$LogLabel, [int]$TruncateChars)
        $result = [PSCustomObject]@{
            Label      = $LogLabel
            Path       = $LogPath
            Lines      = [System.Collections.Generic.List[PSCustomObject]]::new()
            ParseError = $null
            Exists     = $false
        }
        if (-not (Test-Path $LogPath)) { $result.ParseError = "Not found: $LogPath"; return $result }
        $result.Exists = $true
        try {
            $tail  = Get-Content $LogPath -Tail $TailLines -ErrorAction Stop
            $reErr = [regex]'ERROR|SEVERE|Exception|OutOfMemory|FATAL|WARN'
            foreach ($line in $tail) {
                if ($reErr.IsMatch($line)) {
                    $sev = "INFO"
                    if ($line -match 'OutOfMemory|FATAL|SEVERE')  { $sev = "CRITICAL" }
                    elseif ($line -match 'ERROR|Exception')        { $sev = "ERROR" }
                    elseif ($line -match 'WARN')                   { $sev = "WARN" }
                    $trimmed = $line.Trim()
                    # PATCH v4.8: use $TruncateChars constant instead of magic 300
                    if ($trimmed.Length -gt $TruncateChars) { $trimmed = $trimmed.Substring(0, $TruncateChars) + "..." }
                    $result.Lines.Add([PSCustomObject]@{ Severity=$sev; Text=$trimmed })
                }
            }
        } catch { $result.ParseError = $_.Exception.Message }
        return $result
    }

    # PATCH v4.8: $TermEvents now an explicit parameter instead of a free
    # variable closed over from job scope. This prevents silent zero-return
    # if the function is ever called before $termEvents is assigned.
    function Get-TermCountFromCache {
        param([string]$ServiceName, [object[]]$TermEvents)
        if (-not $TermEvents) { return 0 }
        return ($TermEvents | Where-Object { $_.Message -like "*$ServiceName*" } | Measure-Object).Count
    }
    #endregion Job inline helpers

    $instanceResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $jobLog          = [System.Collections.Generic.List[string]]::new()

    #region Ping check
    $pingOk = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (-not $pingOk) {
        $out = [System.Collections.Generic.List[string]]::new()
        $out.Add(""); $out.Add("========================================")
        $out.Add("Zone   : $GroupName")
        $out.Add("Server : $ComputerName")
        $out.Add("  ERROR: Host unreachable (no ping response)")
        $out.Add("========================================")
        $instanceResults.Add([PSCustomObject]@{
            ComputerName=$ComputerName; GroupName=$GroupName; Output=$out; CsvRows=$null
            OverallStatus="DOWN"; TomcatVersion=$null; EventLines=@()
            DriveErrors=@(); DriveWarnings=@(); InformantResults=@{}
            GcCollector="N/A"; GcWarnings=@(); GcRecommend=@(); MemPct=0
            CpuAvg=$null; MemUsedGB=0; MemTotalGB=0; MemFreeGB=0
            DrivesSummary=""; Uptime="N/A"; JobLog=$jobLog
            CertResults=@(); GcStats=$null; LogTails=@()
        })
        return $instanceResults
    }
    #endregion Ping check

    #region WinRM session
    $session      = $null
    $sessionError = $null
    # PATCH v4.8: use named constants for timeouts
    $sessionOpts  = New-PSSessionOption -OpenTimeout $WinRmOpenTimeoutMs -OperationTimeout $WinRmOperationTimeoutMs
    try {
        $session = New-PSSession -ComputerName $ComputerName -SessionOption $sessionOpts -ErrorAction Stop
    } catch {
        $sessionError = $_.Exception.Message
        $jobLog.Add("[LOG] $ComputerName : WinRM session failed -- $sessionError")
    }

    if (-not $session) {
        $out = [System.Collections.Generic.List[string]]::new()
        $out.Add(""); $out.Add("========================================")
        $out.Add("Zone   : $GroupName")
        $out.Add("Server : $ComputerName")
        $out.Add("  ERROR: WinRM session failed -- $sessionError")
        $out.Add("========================================")
        $instanceResults.Add([PSCustomObject]@{
            ComputerName=$ComputerName; GroupName=$GroupName; Output=$out; CsvRows=$null
            OverallStatus="DOWN"; TomcatVersion=$null; EventLines=@()
            DriveErrors=@(); DriveWarnings=@(); InformantResults=@{}
            GcCollector="N/A"; GcWarnings=@(); GcRecommend=@(); MemPct=0
            CpuAvg=$null; MemUsedGB=0; MemTotalGB=0; MemFreeGB=0
            DrivesSummary=""; Uptime="N/A"; JobLog=$jobLog
            CertResults=@(); GcStats=$null; LogTails=@()
        })
        return $instanceResults
    }
    #endregion WinRM session

    try {
    #region Bulk remote data collection
        $sysData = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
            $os      = Get-CimInstance Win32_OperatingSystem
            $svcs    = Get-CimInstance Win32_Service
            $disks   = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Sort-Object DeviceID
            $cpuObj  = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor `
                           -Filter "Name='_Total'" -ErrorAction SilentlyContinue
            $cpu     = if ($cpuObj) { [math]::Round($cpuObj.PercentProcessorTime, 1) } else { $null }
            $procs   = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue

            $jvmData   = $null
            $tomcatSvc = $svcs | Where-Object {
                $_.DisplayName -like "*Apache*Tomcat*" -or $_.Name -like "*Tomcat*"
            } | Select-Object -First 1

            if ($tomcatSvc) {
                foreach ($subKey in @(
                    "SOFTWARE\Apache Software Foundation\Procrun 2.0\$($tomcatSvc.Name)\Parameters\Java",
                    "SOFTWARE\WOW6432Node\Apache Software Foundation\Procrun 2.0\$($tomcatSvc.Name)\Parameters\Java"
                )) {
                    $jvm = Get-ItemProperty -Path "HKLM:\$subKey" -ErrorAction SilentlyContinue
                    if ($jvm) { $jvmData = $jvm; break }
                }
            }

            $since      = (Get-Date).AddHours(-24)
            $appEvents  = Get-WinEvent -FilterHashtable @{
                              LogName='Application'; StartTime=$since; Level=@(1,2,3)
                          } -ErrorAction SilentlyContinue |
                          Where-Object { $_.Message -match "Tomcat|catalina|Content Server" } |
                          Select-Object -First 5
            $termEvents = Get-WinEvent -FilterHashtable @{
                              LogName='System'; Id=7031; StartTime=$since
                          } -ErrorAction SilentlyContinue

            $tomcatHome = $null
            if ($tomcatSvc -and $tomcatSvc.PathName) {
                if ($tomcatSvc.PathName -match '^"?([^"]+\\bin\\[^"]+)"?') {
                    $tomcatHome = Split-Path (Split-Path $Matches[1].TrimEnd('"') -Parent) -Parent
                }
            }

            [PSCustomObject]@{
                OS          = $os
                Svcs        = $svcs
                Disks       = $disks
                Cpu         = $cpu
                JvmData     = $jvmData
                Procs       = $procs
                AppEvents   = $appEvents
                TermEvents  = $termEvents
                TomcatHome  = $tomcatHome
            }
        }

        $os         = $sysData.OS
        $allSvcs    = $sysData.Svcs
        $allDisks   = $sysData.Disks
        $cpuAvg     = $sysData.Cpu
        $jvmReg     = $sysData.JvmData
        $allProcs   = $sysData.Procs
        $rawEvents  = $sysData.AppEvents
        $termEvents = $sysData.TermEvents   # used exclusively via Get-TermCountFromCache param
        $tomcatHome = $sysData.TomcatHome
    #endregion Bulk remote data collection

    #region System metrics
        $totalMemGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeMemGB  = [math]::Round($os.FreePhysicalMemory     / 1MB, 2)
        $usedMemGB  = [math]::Round($totalMemGB - $freeMemGB, 2)
        $memPct     = if ($totalMemGB -gt 0) { [math]::Round(($usedMemGB / $totalMemGB) * 100, 1) } else { 0 }
        $bootAge    = (Get-Date) - $os.LastBootUpTime
        $uptimeStr  = "{0}d {1}h {2}m (booted: {3})" -f `
                          $bootAge.Days, $bootAge.Hours, $bootAge.Minutes, `
                          $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
        $recentTag  = if ($bootAge.TotalHours -lt 24) { "  [WARN - Recent Reboot]" } else { "" }

        $driveErrors   = [System.Collections.Generic.List[string]]::new()
        $driveWarnings = [System.Collections.Generic.List[string]]::new()
        $drivesSumCsv  = ($allDisks | ForEach-Object {
            $t = [math]::Round($_.Size/1GB,2)
            $f = [math]::Round($_.FreeSpace/1GB,2)
            $u = [math]::Round($t - $f, 2)
            $p = if ($t -gt 0) { [math]::Round(($u / $t) * 100, 1) } else { 0 }
            # #5: use param thresholds; #10: also flag on absolute free space
            $absCrit = ($f -lt $DriveCritFreeGB)
            if ($p -ge $DriveCritPct -or $absCrit) {
                $reason = if ($absCrit -and $p -lt $DriveCritPct) { "only ${f} GB free" } else { "$p% used" }
                $driveErrors.Add("$($_.DeviceID) $reason ($u/$t GB)")
            } elseif ($p -ge $DriveWarnPct) {
                $driveWarnings.Add("$($_.DeviceID) $p% used ($u/$t GB)")
            }
            "$($_.DeviceID) $p% ($u/$t GB)"
        }) -join " | "

        $driveSummary = if ($allDisks) {
            ($allDisks | ForEach-Object {
                $tGB = [math]::Round($_.Size/1GB,2)
                $fGB = [math]::Round($_.FreeSpace/1GB,2)
                $uGB = [math]::Round($tGB - $fGB, 2)
                $pct = if ($tGB -gt 0) { [math]::Round(($uGB / $tGB) * 100, 1) } else { 0 }
                # #5/#10: consistent with above
                $absCrit = ($fGB -lt $DriveCritFreeGB)
                $isCrit  = $pct -ge $DriveCritPct -or $absCrit
                $pfx     = if ($isCrit) { "[DRIVE_CRITICAL] " } else { "" }
                $absNote = if ($absCrit -and $pct -lt $DriveCritPct) { "  [LOW FREE SPACE: ${fGB} GB]" } else { "" }
                "{0}    {1}  {2} {3}% used  ({4} GB / {5} GB)  Free: {6} GB{7}{8}" -f `
                    $pfx, $_.DeviceID, (Get-VisualBar -Pct $pct), $pct, $uGB, $tGB, $fGB,
                    (Get-ThresholdTag -Pct $pct), $absNote
            }) -join "`n"
        } else { "    No fixed drives found." }
    #endregion System metrics

    #region Event log lines
        $eventLines = [System.Collections.Generic.List[string]]::new()
        if ($rawEvents) {
            foreach ($ev in $rawEvents) {
                $lvl = switch ($ev.Level) { 1{"ERROR"} 2{"ERROR"} 3{"WARN"} default{"INFO"} }
                $msg = ($ev.Message -split "`n")[0].Trim()
                if ($msg.Length -gt 200) { $msg = $msg.Substring(0,200) + "..." }
                $eventLines.Add("[$lvl] $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))  $($ev.ProviderName): $msg")
            }
        }
    #endregion Event log lines

    #region Locate services
        $tomcatSvc = $allSvcs | Where-Object {
            $_.DisplayName -like "*Apache*Tomcat*" -or $_.Name -like "*Tomcat*"
        } | Select-Object -First 1

        $csSvcs = @($allSvcs | Where-Object {
            $_.Description -like "*Content Server*" -and
            $_.Description -notlike "*Content Server Admin*"
        } | Sort-Object Name -Unique)

        $csAdmin = $allSvcs | Where-Object {
            $_.Description -like "*Content Server Admin*"
        } | Select-Object -First 1
    #endregion Locate services

    #region JVM / GC config from registry
        $tomcatVersion = "N/A"
        $jrePath       = "N/A"
        $heapInitMB    = $null
        $heapMaxMB     = $null
        $gcCollector   = "N/A"
        $gcLoggingOn   = $false
        $gcWarnings    = [System.Collections.Generic.List[string]]::new()
        $gcRecommend   = [System.Collections.Generic.List[string]]::new()

        if ($jvmReg) {
            if ($jvmReg.Jvm) {
                $jrePath = Split-Path (Split-Path (Split-Path $jvmReg.Jvm -Parent) -Parent) -Parent
            }
            $optFlat = if ($jvmReg.Options) { $jvmReg.Options -join ' ' } else { "" }
            if ($optFlat -match '(?:^|\s)-Xms(\d+)([kmgKMG]?)') {
                $val  = $Matches[1]; $unit = $Matches[2]
                $heapInitMB = switch ($unit.ToUpper()) {
                    'K' { [math]::Round($val / 1KB, 0) }
                    'M' { [int]$val }
                    'G' { [int]$val * 1024 }
                    default { [math]::Round($val / 1MB, 0) }
                }
            }
            if ($optFlat -match '(?:^|\s)-Xmx(\d+)([kmgKMG]?)') {
                $val  = $Matches[1]; $unit = $Matches[2]
                $heapMaxMB = switch ($unit.ToUpper()) {
                    'K' { [math]::Round($val / 1KB, 0) }
                    'M' { [int]$val }
                    'G' { [int]$val * 1024 }
                    default { [math]::Round($val / 1MB, 0) }
                }
            }
            if ($optFlat -match '-XX:\+Use(\w+)GC') { $gcCollector = $Matches[1] + "GC" }
            if ($optFlat -match '-Xlog:gc|-XX:\+PrintGCDetails|-verbose:gc') { $gcLoggingOn = $true }

            if ($heapInitMB -and $heapMaxMB -and ($heapInitMB -ne $heapMaxMB)) {
                $gcWarnings.Add("Xms ($heapInitMB MB) != Xmx ($heapMaxMB MB) -- JVM will resize heap at runtime")
                $gcRecommend.Add("Set Xms = Xmx to pre-allocate heap and avoid resize pauses")
            }
            if ($heapMaxMB -and $heapMaxMB -lt 1024) {
                $gcWarnings.Add("Xmx is only $heapMaxMB MB -- likely undersized for Content Server")
                $gcRecommend.Add("Increase Xmx to at least 2048 MB for production")
            }
            if (-not $gcLoggingOn) {
                $gcWarnings.Add("GC logging not enabled -- add -Xlog:gc* (JDK9+) or -XX:+PrintGCDetails (JDK8)")
                $gcRecommend.Add("Enable GC logging to allow thrashing detection in future runs")
            }
        }
    #endregion JVM / GC config from registry

    #region Tomcat version detection
    # PATCH v4.8: was always "N/A". Now reads from RELEASE-NOTES first,
    # then falls back to catalina.jar manifest, then version.txt.
    if ($tomcatHome) {
        $tomcatVersion = Invoke-Command -Session $session -ErrorAction SilentlyContinue -ScriptBlock {
            param($home)
            # Strategy 1: RELEASE-NOTES (most reliable, plain text, first 10 lines)
            $rn = Join-Path $home "RELEASE-NOTES"
            if (Test-Path $rn) {
                $match = Get-Content $rn -TotalCount 10 |
                         Select-String 'Apache Tomcat[^\d]*(\d+\.\d+[\.\d]*)' |
                         Select-Object -First 1
                if ($match) {
                    return $match.Matches[0].Groups[1].Value
                }
            }
            # Strategy 2: catalina.jar MANIFEST.MF Implementation-Version
            $jar = Join-Path $home "lib\catalina.jar"
            if (Test-Path $jar) {
                Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
                try {
                    $zip = [System.IO.Compression.ZipFile]::OpenRead($jar)
                    $mf  = $zip.Entries | Where-Object { $_.FullName -eq 'META-INF/MANIFEST.MF' } |
                           Select-Object -First 1
                    if ($mf) {
                        $reader  = New-Object System.IO.StreamReader($mf.Open())
                        $content = $reader.ReadToEnd()
                        $reader.Close()
                        $zip.Dispose()
                        if ($content -match 'Implementation-Version:\s*([\d\.]+)') {
                            return $Matches[1]
                        }
                    } else { $zip.Dispose() }
                } catch { }
            }
            # Strategy 3: version.txt (some Windows installers write this)
            $vt = Join-Path $home "version.txt"
            if (Test-Path $vt) {
                $match = Get-Content $vt -TotalCount 5 |
                         Select-String '(\d+\.\d+[\.\d]*)' |
                         Select-Object -First 1
                if ($match) { return $match.Matches[0].Groups[1].Value }
            }
            return "Unknown"
        } -ArgumentList $tomcatHome

        if (-not $tomcatVersion) { $tomcatVersion = "Unknown" }
    }
    #endregion Tomcat version detection

    #region Working set / heap usage
        $wsMB = $null
        if ($tomcatSvc -and $tomcatSvc.State -eq "Running" -and $tomcatSvc.ProcessId -gt 0) {
            $proc = $allProcs | Where-Object { $_.ProcessId -eq $tomcatSvc.ProcessId } | Select-Object -First 1
            if ($proc) { $wsMB = [math]::Round($proc.WorkingSetSize / 1MB, 1) }
        }
        $jvmHeapText   = if ($wsMB) { "Working Set: ${wsMB} MB" } else { "N/A" }
        $jvmHeapCsvStr = if ($wsMB) { "${wsMB} MB" } else { "N/A" }
        if ($heapInitMB -or $heapMaxMB) {
            $heapCfg       = "Xms: $(if ($heapInitMB) { "${heapInitMB} MB" } else { '?' })  Xmx: $(if ($heapMaxMB) { "${heapMaxMB} MB" } else { '?' })"
            $jvmHeapText   = "$jvmHeapText  |  $heapCfg"
            $jvmHeapCsvStr = "$jvmHeapCsvStr | $heapCfg"
        }
        $heapUsagePct = $null
        if ($wsMB -and $heapMaxMB -and $heapMaxMB -gt 0) {
            $heapUsagePct = [math]::Round(($wsMB / $heapMaxMB) * 100, 1)
        }
    #endregion Working set / heap usage

    #region Service helpers
        # NOTE: Get-SvcUptimeFromProcs reads $allProcs from job scope only.
        # It does NOT use $session and makes no remote calls.
        function Get-SvcUptimeFromProcs {
            param([int]$ProcessId)
            if ($ProcessId -gt 0) {
                $p = $allProcs | Where-Object { $_.ProcessId -eq $ProcessId } | Select-Object -First 1
                if ($p -and $p.CreationDate) {
                    $rt = (Get-Date) - $p.CreationDate
                    $s  = if ($rt.Days -gt 0) { "{0}d {1}h {2}m" -f $rt.Days, $rt.Hours, $rt.Minutes }
                          elseif ($rt.Hours -gt 0) { "{0}h {1}m" -f $rt.Hours, $rt.Minutes }
                          else { "{0}m {1}s" -f $rt.Minutes, $rt.Seconds }
                    return "$s (started: $($p.CreationDate.ToString('yyyy-MM-dd HH:mm:ss')))"
                }
            }
            return "N/A"
        }

        function Get-RestartConfig {
            param([string]$ServiceName)
            $r = Invoke-Command -Session $session -ErrorAction SilentlyContinue -ScriptBlock {
                param($sn, $resetSec, $delayMs)
                $scExe = "$env:SystemRoot\System32\sc.exe"
                $count = (& $scExe qfailure $sn 2>&1 | Select-String "RESTART" | Measure-Object).Count
                if ($count -ne 3) {
                    # PATCH v4.8: use passed-in constants instead of magic numbers
                    $actions = "restart/$delayMs/restart/$delayMs/restart/$delayMs"
                    & $scExe failure $sn reset= $resetSec actions= $actions 2>&1 | Out-Null
                    $count = (& $scExe qfailure $sn 2>&1 | Select-String "RESTART" | Measure-Object).Count
                    return [PSCustomObject]@{ Count=$count; Updated=$true }
                }
                return [PSCustomObject]@{ Count=$count; Updated=$false }
            } -ArgumentList $ServiceName, $ScFailureResetSec, $ScRestartDelayMs
            if ($r) {
                $disp    = "$($r.Count) restart action(s) configured$(if ($r.Updated) { ' [updated]' } else { ' [OK]' })"
                $logNote = if ($r.Updated) { "Restart config updated on $ServiceName" } else { $null }
                return [PSCustomObject]@{ Display=$disp; LogNote=$logNote }
            }
            return [PSCustomObject]@{ Display="N/A"; LogNote=$null }
        }

        function Invoke-AutoRestartRemote {
            param([string]$ServiceName, [bool]$Enabled)
            if (-not $Enabled) { return $null }
            try {
                $state = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
                    param($sn)
                    $svc = Get-Service -Name $sn -ErrorAction Stop
                    if ($svc.Status -ne 'Running') {
                        Start-Service -Name $sn -ErrorAction Stop
                        $deadline = (Get-Date).AddSeconds(30)
                        while ((Get-Date) -lt $deadline) {
                            Start-Sleep -Milliseconds 500
                            $svc = Get-Service -Name $sn -ErrorAction SilentlyContinue
                            if ($svc -and $svc.Status -eq 'Running') { break }
                        }
                        return $svc.Status.ToString()
                    }
                    return $null
                } -ArgumentList $ServiceName
                if ($state) { return "Auto-restart attempted: now $state" }
            } catch { return "Auto-restart FAILED: $_" }
            return $null
        }

        # #7: only re-poll when AutoRestartStopped is active (we may have just
        # issued a restart). Uses a short poll loop rather than a blind sleep so
        # it exits as soon as the service comes up, up to a 30-second ceiling.
        function Get-ServiceStateWithRetry {
            param([string]$ServiceName)
            $svc = $allSvcs | Where-Object { $_.Name -eq $ServiceName } | Select-Object -First 1
            if ($svc -and $svc.State -ne "Running" -and $AutoRestartStopped) {
                $deadline = (Get-Date).AddSeconds(30)
                while ((Get-Date) -lt $deadline) {
                    Start-Sleep -Milliseconds 500
                    $refreshed = Invoke-Command -Session $session -ErrorAction SilentlyContinue -ScriptBlock {
                        param($n) Get-CimInstance Win32_Service -Filter "Name='$n'"
                    } -ArgumentList $ServiceName
                    if ($refreshed) {
                        if ($refreshed.State -eq "Running") { return $refreshed }
                        $svc = $refreshed
                    }
                }
                # Return the last known state after deadline
                return $svc
            }
            return $svc
        }
    #endregion Service helpers

    #region Certificate check
        # Only attempt TLS inspection on ports confirmed open during pre-flight.
        # $sysData does not carry TCP results, so we re-probe here with a short
        # timeout. This avoids a 5-second hang per port when neither 443 nor 8443
        # is listening, and prevents false cert-expiry alerts for closed ports.
        $certPorts = @(443, 8443) | Where-Object {
            $portOpen = $false
            $tc = New-Object System.Net.Sockets.TcpClient
            try {
                $ar      = $tc.BeginConnect($ComputerName, $_, $null, $null)
                $portOpen = $ar.AsyncWaitHandle.WaitOne(2000, $false) -and $tc.Connected
                if ($portOpen) { try { $tc.EndConnect($ar) } catch {} }
            } catch {}
            finally { $tc.Close() }
            $portOpen
        }

        $certResults = if ($certPorts.Count -gt 0) {
            $jobLog.Add("[LOG] $ComputerName : checking TLS on port(s): $($certPorts -join ', ')")
            Get-TlsCertInfo -HostName $ComputerName -Ports $certPorts
        } else {
            $jobLog.Add("[LOG] $ComputerName : ports 443 and 8443 both closed — skipping cert check")
            @()
        }
    #endregion Certificate check

    #region GC log analysis and log tailing
        $gcStats  = $null
        $logTails = [System.Collections.Generic.List[PSCustomObject]]::new()

        if ($tomcatHome) {
            $catalinaLog = $null
            $candidates  = @(
                "$tomcatHome\logs\catalina.out",
                "$tomcatHome\logs\catalina.$(Get-Date -Format 'yyyy-MM-dd').log"
            )
            foreach ($c in $candidates) {
                $exists = Invoke-Command -Session $session -ErrorAction SilentlyContinue -ScriptBlock {
                    param($p); Test-Path $p
                } -ArgumentList $c
                if ($exists) { $catalinaLog = $c; break }
            }

            if ($catalinaLog) {
                $fetchLines  = [math]::Max($LogTailLines, $GcTailLines)
                $remoteLines = Invoke-Command -Session $session -ErrorAction SilentlyContinue -ScriptBlock {
                    param($p, $n)
                    Get-Content $p -Tail $n -ErrorAction SilentlyContinue
                } -ArgumentList $catalinaLog, $fetchLines

                if ($remoteLines) {
                    # PATCH v4.8: try/finally ensures temp file cleanup even if
                    # Get-GcStats or Get-LogTail throw mid-execution
                    $tmpPath = [System.IO.Path]::GetTempFileName()
                    try {
                        $remoteLines | Set-Content $tmpPath -Encoding UTF8
                        $gcStats    = Get-GcStats  -LogPath $tmpPath -LookbackHours 1
                        $tailResult = Get-LogTail  -LogPath $tmpPath -TailLines $LogTailLines `
                                          -LogLabel "catalina.out" -TruncateChars $LogLineTruncateChars
                        $tailResult.Path = $catalinaLog
                        $logTails.Add($tailResult)
                    } finally {
                        Remove-Item $tmpPath -Force -ErrorAction SilentlyContinue
                    }
                }
            } else {
                $logTails.Add([PSCustomObject]@{
                    Label="catalina.out"; Path="unknown"; Exists=$false
                    Lines=[System.Collections.Generic.List[PSCustomObject]]::new()
                    ParseError="Could not resolve Tomcat log path under $tomcatHome\logs"
                })
            }
        } else {
            $logTails.Add([PSCustomObject]@{
                Label="catalina.out"; Path="unknown"; Exists=$false
                Lines=[System.Collections.Generic.List[PSCustomObject]]::new()
                ParseError="Could not resolve Tomcat home directory from service path"
            })
        }

        foreach ($cs in $csSvcs) {
            $csLogDir = "$CsLogRoot\$($cs.Name)\dacs\contentserver_logs\thread_logs"
            $remoteCSResult = Invoke-Command -Session $session -ErrorAction SilentlyContinue -ScriptBlock {
                param($dir, $n)
                if (-not (Test-Path $dir)) { return $null }
                $latest = Get-ChildItem -Path $dir -Filter "thread*.out" -File -ErrorAction SilentlyContinue |
                              ForEach-Object {
                                  $num = 0
                                  if ($_.BaseName -match '(\d+)$') { $num = [int]$Matches[1] }
                                  [PSCustomObject]@{ File=$_; Num=$num }
                              } |
                              Sort-Object Num -Descending |
                              Select-Object -First 1 -ExpandProperty File
                if (-not $latest) {
                    $latest = Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
                                  Sort-Object LastWriteTime -Descending |
                                  Select-Object -First 1
                }
                if (-not $latest) { return $null }
                [PSCustomObject]@{
                    Path  = $latest.FullName
                    Lines = (Get-Content $latest.FullName -Tail $n -ErrorAction SilentlyContinue)
                }
            } -ArgumentList $csLogDir, $LogTailLines

            if ($remoteCSResult -and $remoteCSResult.Lines) {
                # PATCH v4.8: try/finally for CS log temp file cleanup
                $tmpCS = [System.IO.Path]::GetTempFileName()
                try {
                    $remoteCSResult.Lines | Set-Content $tmpCS -Encoding UTF8
                    $csTail = Get-LogTail -LogPath $tmpCS -TailLines $LogTailLines `
                                  -LogLabel "CS thread log ($($cs.Name))" -TruncateChars $LogLineTruncateChars
                    $csTail.Path = $remoteCSResult.Path
                    $logTails.Add($csTail)
                } finally {
                    Remove-Item $tmpCS -Force -ErrorAction SilentlyContinue
                }
            } else {
                $logTails.Add([PSCustomObject]@{
                    Label      = "CS thread log ($($cs.Name))"
                    Path       = $csLogDir
                    Exists     = $false
                    Lines      = [System.Collections.Generic.List[PSCustomObject]]::new()
                    ParseError = "No thread*.out files found in $csLogDir"
                })
            }
        }
    #endregion GC log analysis and log tailing

    #region Overall status seed
        $checkTime     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $csvRows       = [System.Collections.Generic.List[PSCustomObject]]::new()
        $overallStatus = "OK"
        $allInformant  = [ordered]@{}

        if ($driveErrors.Count -gt 0)               { $overallStatus = Set-OverallStatus $overallStatus "CRITICAL" }
        if ($memPct -ge 90)                         { $overallStatus = Set-OverallStatus $overallStatus "CRITICAL" }
        if ($null -ne $cpuAvg -and $cpuAvg -ge 90)  { $overallStatus = Set-OverallStatus $overallStatus "CRITICAL" }
        if ($memPct -ge 75)                         { $overallStatus = Set-OverallStatus $overallStatus "WARN" }
        if ($null -ne $cpuAvg -and $cpuAvg -ge 75)  { $overallStatus = Set-OverallStatus $overallStatus "WARN" }
        if ($driveWarnings.Count -gt 0)             { $overallStatus = Set-OverallStatus $overallStatus "WARN" }
        if ($recentTag -ne "")                      { $overallStatus = Set-OverallStatus $overallStatus "WARN" }

        foreach ($cert in $certResults) {
            if ($cert.Error)                            { $overallStatus = Set-OverallStatus $overallStatus "WARN" }
            elseif ($cert.DaysLeft -le $CertCritDays)  { $overallStatus = Set-OverallStatus $overallStatus "CRITICAL" }
            elseif ($cert.DaysLeft -le $CertWarnDays)  { $overallStatus = Set-OverallStatus $overallStatus "WARN" }
        }

        if ($gcStats -and -not $gcStats.ParseError) {
            if ($gcStats.OomFound)                                       { $overallStatus = Set-OverallStatus $overallStatus "CRITICAL" }
            if ($gcStats.MaxPauseMs -ge $GcPauseWarnMs)                 { $overallStatus = Set-OverallStatus $overallStatus "WARN" }
            if ($gcStats.CountPerHour -ge $GcFreqWarnPerHour)           { $overallStatus = Set-OverallStatus $overallStatus "WARN" }
            if ($gcStats.HeapTrendMB -and $gcStats.HeapTrendMB -gt 200) { $overallStatus = Set-OverallStatus $overallStatus "WARN" }
        }

        foreach ($tail in $logTails) {
            $critLine = $tail.Lines | Where-Object { $_.Severity -eq "CRITICAL" } | Select-Object -First 1
            $errLine  = $tail.Lines | Where-Object { $_.Severity -eq "ERROR" }    | Select-Object -First 1
            if ($critLine)      { $overallStatus = Set-OverallStatus $overallStatus "CRITICAL" }
            elseif ($errLine)   { $overallStatus = Set-OverallStatus $overallStatus "WARN" }
        }
    #endregion Overall status seed

    #region Console header
        $cpuLine = if ($null -ne $cpuAvg) {
            "$(Get-VisualBar -Pct $cpuAvg) $cpuAvg%$(Get-ThresholdTag -Pct $cpuAvg)"
        } else { "N/A (WMI perf counter unavailable)" }

        $csInstanceNames = ($csSvcs | Select-Object -ExpandProperty Name -Unique) -join ", "
        $csInstanceLine  = if ($csInstanceNames) { $csInstanceNames } else { "none found" }

        $out = [System.Collections.Generic.List[string]]::new()
        $out.Add("")
        $out.Add("========================================")
        $out.Add("Zone       : $GroupName")
        $out.Add("Server     : $ComputerName")
        $out.Add("CS Instance: $csInstanceLine")
        $out.Add("  Server Uptime: $uptimeStr$recentTag")
        $out.Add("  Memory       : $(Get-VisualBar -Pct $memPct) $memPct% used  ($usedMemGB GB / $totalMemGB GB)  Free: $freeMemGB GB$(Get-ThresholdTag -Pct $memPct)")
        $out.Add("  CPU          : $cpuLine")
        $out.Add("  Drives:")
        foreach ($dline in ($driveSummary -split "`n")) { $out.Add($dline) }
        if ($driveErrors.Count -gt 0)   { $out.Add("  [ERROR] Drive critical: " + ($driveErrors -join "; ")) }
        if ($driveWarnings.Count -gt 0) { $out.Add("  [WARN]  Drive warning:  " + ($driveWarnings -join "; ")) }
        $out.Add("========================================")
    #endregion Console header

    #region TLS certificate output
        $out.Add("")
        $out.Add("TLS Certificates:")
        if ($certResults.Count -eq 0) {
            $out.Add("  No HTTPS ports responded (443, 8443)")
        } else {
            foreach ($cert in $certResults) {
                if ($cert.Error) {
                    $out.Add("  Port $($cert.Port): [ERROR] $($cert.Error)")
                } else {
                    $tag = if ($cert.DaysLeft -le $CertCritDays)     { " [CRITICAL - EXPIRING SOON]" }
                           elseif ($cert.DaysLeft -le $CertWarnDays) { " [WARN]" }
                           else { " [OK]" }
                    $out.Add("  Port $($cert.Port):$tag")
                    $out.Add("    Subject   : $($cert.Subject)")
                    $out.Add("    Expiry    : $($cert.Expiry)  ($($cert.DaysLeft) days remaining)")
                    $out.Add("    Issuer    : $($cert.Issuer)")
                    $out.Add("    Thumbprint: $($cert.Thumbprint)")
                }
            }
        }
    #endregion TLS certificate output

    #region Tomcat
        $out.Add("")
        $out.Add("Tomcat Service:")
        if ($tomcatSvc) {
            $autoNote = Invoke-AutoRestartRemote -ServiceName $tomcatSvc.Name -Enabled $AutoRestartStopped
            if ($autoNote) { $out.Add("  [AUTO-RESTART] $autoNote") }
            $tomcatSvc = Get-ServiceStateWithRetry -ServiceName $tomcatSvc.Name
            if ($tomcatSvc -and $tomcatSvc.State -ne "Running") {
                $overallStatus = Set-OverallStatus $overallStatus "DOWN"
            }

            $tState = if ($tomcatSvc.State -eq "Running") { "[RUNNING]" } else { "[STOPPED]" }
            $tUp    = Get-SvcUptimeFromProcs -ProcessId $tomcatSvc.ProcessId
            $tRC    = Get-RestartConfig -ServiceName $tomcatSvc.Name
            if ($tRC.LogNote) { $jobLog.Add("[LOG] $($tRC.LogNote)") }
            # PATCH v4.8: pass $termEvents explicitly
            $tTerms = Get-TermCountFromCache -ServiceName $tomcatSvc.Name -TermEvents $termEvents

            $heapUsageLine = if ($null -ne $heapUsagePct) {
                "$(Get-VisualBar -Pct $heapUsagePct) $heapUsagePct% of Xmx$(Get-ThresholdTag -Pct $heapUsagePct)"
            } else { $jvmHeapText }

            $out.Add("  Name:               $($tomcatSvc.Name)")
            $out.Add("  Status:             $tState")
            $out.Add("  Display Name:       $($tomcatSvc.DisplayName)")
            $out.Add("  Version:            $tomcatVersion")
            $out.Add("  JRE Path:           $jrePath")
            $out.Add("  Run As:             $($tomcatSvc.StartName)")
            $out.Add("  Service Uptime:     $tUp")
            $out.Add("  Restart Config:     $($tRC.Display)")
            $out.Add("  Unexp.Terms (24h):  $tTerms")
            $out.Add("  Heap Usage:         $heapUsageLine")
            $out.Add("  GC Collector:       $gcCollector")
            $out.Add("  GC Logging:         $(if ($gcLoggingOn) { '[ENABLED]' } else { '[DISABLED] -- blind to heap thrashing' })")
            foreach ($w  in $gcWarnings)  { $out.Add("  [WARN] GC: $w") }
            foreach ($r2 in $gcRecommend) { $out.Add("  [INFO] GC Rec: $r2") }

            if ($gcStats) {
                $out.Add("")
                $out.Add("  GC Activity (last 1 hour from catalina.out):")
                if ($gcStats.ParseError) {
                    $out.Add("    [WARN] Could not parse GC log: $($gcStats.ParseError)")
                } elseif ($gcStats.Events.Count -eq 0) {
                    $out.Add("    No GC events found in last hour (GC logging may be disabled or no collections occurred)")
                } else {
                    $thrashTag = if ($gcStats.CountPerHour -ge $GcFreqWarnPerHour) { " [WARN - HIGH FREQUENCY]" } else { "" }
                    $pauseTag  = if ($gcStats.MaxPauseMs  -ge $GcPauseWarnMs)      { " [WARN - LONG PAUSE]" }     else { "" }
                    $trendTag  = if ($gcStats.HeapTrendMB -and $gcStats.HeapTrendMB -gt 200)    { " [WARN - GROWING]" } `
                                 elseif ($gcStats.HeapTrendMB -and $gcStats.HeapTrendMB -lt -50) { " [reclaiming]" } `
                                 else { "" }
                    $out.Add("    Collections/hr : $($gcStats.CountPerHour)$thrashTag")
                    $out.Add("    Max pause      : $($gcStats.MaxPauseMs) ms$pauseTag")
                    $out.Add("    Avg pause      : $($gcStats.AvgPauseMs) ms")
                    if ($null -ne $gcStats.HeapTrendMB) {
                        $sign = if ($gcStats.HeapTrendMB -ge 0) { "+" } else { "" }
                        $out.Add("    Heap trend     : ${sign}$($gcStats.HeapTrendMB) MB over last hour$trendTag")
                    }
                    if ($gcStats.OomFound) { $out.Add("    [CRITICAL] OutOfMemoryError detected in log!") }
                    $worst = $gcStats.Events | Sort-Object PauseMs -Descending | Select-Object -First 3
                    if ($worst) {
                        $out.Add("    Worst pauses:")
                        foreach ($ev in $worst) {
                            $out.Add("      $($ev.Timestamp)  $($ev.Type)  $($ev.PauseMs) ms  heap after: $($ev.HeapAfterMB)/$($ev.HeapMaxMB) MB")
                        }
                    }
                }
            }

            $csvRows.Add([PSCustomObject]@{
                DateTime            = $checkTime
                Zone                = $GroupName
                Server              = $ComputerName
                ServiceType         = "Tomcat"
                ServiceName         = $tomcatSvc.Name
                DisplayName         = $tomcatSvc.DisplayName
                Description         = ""
                Status              = $tomcatSvc.State
                Version             = $tomcatVersion
                JrePath             = $jrePath
                HeapInitMB          = $heapInitMB
                HeapMaxMB           = $heapMaxMB
                HeapUsagePct        = $heapUsagePct
                GcCollector         = $gcCollector
                GcLoggingEnabled    = $gcLoggingOn
                GcCollectionsPerHr  = if ($gcStats) { $gcStats.CountPerHour } else { $null }
                GcMaxPauseMs        = if ($gcStats) { $gcStats.MaxPauseMs }   else { $null }
                GcAvgPauseMs        = if ($gcStats) { $gcStats.AvgPauseMs }   else { $null }
                GcHeapTrendMB       = if ($gcStats) { $gcStats.HeapTrendMB }  else { $null }
                OomDetected         = if ($gcStats) { $gcStats.OomFound }     else { $false }
                GcWarnings          = ($gcWarnings  -join " | ")
                GcRecommend         = ($gcRecommend -join " | ")
                RunAs               = $tomcatSvc.StartName
                ServiceUptime       = $tUp
                RestartConfig       = $tRC.Display
                UnexpTerms24h       = $tTerms
                WorkingSetMB        = $jvmHeapCsvStr
                ServerUptime        = $uptimeStr
                RecentReboot        = ($recentTag -ne "")
                CpuPct              = $cpuAvg
                MemPct              = $memPct
                MemUsedGB           = $usedMemGB
                MemTotalGB          = $totalMemGB
                MemFreeGB           = $freeMemGB
                DrivesSummary       = $drivesSumCsv
                OverallStatus       = $overallStatus
            })
        } else {
            $out.Add("  NOT FOUND")
        }
    #endregion Tomcat

    #region Content Server
        $out.Add("")
        $out.Add("Content Server Service(s):")
        if ($csSvcs) {
            foreach ($cs in $csSvcs) {
                $autoNote = Invoke-AutoRestartRemote -ServiceName $cs.Name -Enabled $AutoRestartStopped
                if ($autoNote) { $out.Add("  [AUTO-RESTART] $autoNote") }
                $cs = Get-ServiceStateWithRetry -ServiceName $cs.Name
                if ($cs -and $cs.State -ne "Running") {
                    $overallStatus = Set-OverallStatus $overallStatus "DOWN"
                }

                $csState = if ($cs.State -eq "Running") { "[RUNNING]" } else { "[STOPPED]" }
                $csUp    = Get-SvcUptimeFromProcs -ProcessId $cs.ProcessId
                $csRC    = Get-RestartConfig -ServiceName $cs.Name
                if ($csRC.LogNote) { $jobLog.Add("[LOG] $($csRC.LogNote)") }
                # PATCH v4.8: pass $termEvents explicitly
                $csTerms = Get-TermCountFromCache -ServiceName $cs.Name -TermEvents $termEvents

                $out.Add("")
                $out.Add("  Instance:           $($cs.Name)")
                $out.Add("  Status:             $csState")
                $out.Add("  Display Name:       $($cs.DisplayName)")
                $out.Add("  Description:        $($cs.Description)")
                $out.Add("  Run As:             $($cs.StartName)")
                $out.Add("  Service Uptime:     $csUp")
                $out.Add("  Restart Config:     $($csRC.Display)")
                $out.Add("  Unexp.Terms (24h):  $csTerms")

                $csInformant = @{}
                if ($cs.State -eq "Running") {
                    # #1: explicit bool cast guards against "True"/"False" string
                    # serialization artefacts from Start-Job argument marshalling.
                    $scheme   = if ([bool]$CsUseHttps) { "https" } else { "http" }
                    $pingBase = "${scheme}://$ComputerName/$($cs.Name)/cs?func=informant.ping"
                    # #8: use the configurable component list
                    $components = $InformantComponents
                    $out.Add("")
                    $out.Add("  Informant Health Checks (parallel):")
                    $iResults = Invoke-InformantChecks -BaseUrl $pingBase -Components $components `
                                    -TimeoutSec $WebTimeoutSec -WarnMs $InformantWarnMs
                    foreach ($comp in $components) {
                        $ir      = $iResults[$comp]
                        $msLabel = "[$($ir.Ms)ms]"
                        $slowTag = if ($ir.Ms -ge $InformantWarnMs) { " [SLOW]" } else { "" }
                        if ($ir.Error) {
                            $out.Add("    $comp : [ERROR] - $($ir.Error) $msLabel")
                            $overallStatus = Set-OverallStatus $overallStatus "WARN"
                            $csInformant[$comp] = [PSCustomObject]@{
                                Status="ERROR"; Detail=$ir.Error; Ms=$ir.Ms; Slow=($ir.Ms -ge $InformantWarnMs)
                            }
                        } else {
                            $tag    = if ($ir.Content -match "=\s*success") { "SUCCESS" }
                                      elseif ($ir.Content -match "=\s*failure") { "FAILURE" }
                                      else { "OTHER" }
                            $detail = if ($tag -eq "OTHER") { $ir.Content } else { "" }
                            if ($tag -eq "FAILURE") { $overallStatus = Set-OverallStatus $overallStatus "CRITICAL" }
                            $out.Add("    $comp : [$tag] $msLabel$slowTag")
                            $csInformant[$comp] = [PSCustomObject]@{
                                Status=$tag; Detail=$detail; Ms=$ir.Ms; Slow=($ir.Ms -ge $InformantWarnMs)
                            }
                        }
                    }
                    $out.Add("")
                    $out.Add("  --- System Resources ---")
                    $out.Add("  CPU : $cpuLine")
                } else {
                    $out.Add("  [INFO] Skipped Informant checks -- service not running")
                }

                $allInformant[$cs.Name] = $csInformant
                $csvRows.Add([PSCustomObject]@{
                    DateTime            = $checkTime
                    Zone                = $GroupName
                    Server              = $ComputerName
                    ServiceType         = "ContentServer"
                    ServiceName         = $cs.Name
                    DisplayName         = $cs.DisplayName
                    Description         = $cs.Description
                    Status              = $cs.State
                    Version             = ""
                    JrePath             = ""
                    HeapInitMB          = $null
                    HeapMaxMB           = $null
                    HeapUsagePct        = $null
                    GcCollector         = ""
                    GcLoggingEnabled    = $false
                    GcCollectionsPerHr  = $null
                    GcMaxPauseMs        = $null
                    GcAvgPauseMs        = $null
                    GcHeapTrendMB       = $null
                    OomDetected         = $false
                    GcWarnings          = ""
                    GcRecommend         = ""
                    RunAs               = $cs.StartName
                    ServiceUptime       = $csUp
                    RestartConfig       = $csRC.Display
                    UnexpTerms24h       = $csTerms
                    WorkingSetMB        = "N/A"
                    ServerUptime        = $uptimeStr
                    RecentReboot        = ($recentTag -ne "")
                    CpuPct              = $cpuAvg
                    MemPct              = $memPct
                    MemUsedGB           = $usedMemGB
                    MemTotalGB          = $totalMemGB
                    MemFreeGB           = $freeMemGB
                    DrivesSummary       = $drivesSumCsv
                    OverallStatus       = $overallStatus
                })
            }
        } else {
            $out.Add("  NOT FOUND")
        }
    #endregion Content Server

    #region CS Admin
        $out.Add("")
        $out.Add("Content Server Admin Service:")
        if ($csAdmin) {
            $autoNote = Invoke-AutoRestartRemote -ServiceName $csAdmin.Name -Enabled $AutoRestartStopped
            if ($autoNote) { $out.Add("  [AUTO-RESTART] $autoNote") }
            $csAdmin = Get-ServiceStateWithRetry -ServiceName $csAdmin.Name
            if ($csAdmin -and $csAdmin.State -ne "Running") {
                $overallStatus = Set-OverallStatus $overallStatus "DOWN"
            }

            $caState = if ($csAdmin.State -eq "Running") { "[RUNNING]" } else { "[STOPPED]" }
            $caUp    = Get-SvcUptimeFromProcs -ProcessId $csAdmin.ProcessId
            $caRC    = Get-RestartConfig -ServiceName $csAdmin.Name
            if ($caRC.LogNote) { $jobLog.Add("[LOG] $($caRC.LogNote)") }
            # PATCH v4.8: pass $termEvents explicitly
            $caTerms = Get-TermCountFromCache -ServiceName $csAdmin.Name -TermEvents $termEvents

            $out.Add("  Name:               $($csAdmin.Name)")
            $out.Add("  Status:             $caState")
            $out.Add("  Display Name:       $($csAdmin.DisplayName)")
            $out.Add("  Description:        $($csAdmin.Description)")
            $out.Add("  Run As:             $($csAdmin.StartName)")
            $out.Add("  Service Uptime:     $caUp")
            $out.Add("  Restart Config:     $($caRC.Display)")
            $out.Add("  Unexp.Terms (24h):  $caTerms")

            $csvRows.Add([PSCustomObject]@{
                DateTime            = $checkTime
                Zone                = $GroupName
                Server              = $ComputerName
                ServiceType         = "ContentServerAdmin"
                ServiceName         = $csAdmin.Name
                DisplayName         = $csAdmin.DisplayName
                Description         = $csAdmin.Description
                Status              = $csAdmin.State
                Version             = ""
                JrePath             = ""
                HeapInitMB          = $null
                HeapMaxMB           = $null
                HeapUsagePct        = $null
                GcCollector         = ""
                GcLoggingEnabled    = $false
                GcCollectionsPerHr  = $null
                GcMaxPauseMs        = $null
                GcAvgPauseMs        = $null
                GcHeapTrendMB       = $null
                OomDetected         = $false
                GcWarnings          = ""
                GcRecommend         = ""
                RunAs               = $csAdmin.StartName
                ServiceUptime       = $caUp
                RestartConfig       = $caRC.Display
                UnexpTerms24h       = $caTerms
                WorkingSetMB        = "N/A"
                ServerUptime        = $uptimeStr
                RecentReboot        = ($recentTag -ne "")
                CpuPct              = $cpuAvg
                MemPct              = $memPct
                MemUsedGB           = $usedMemGB
                MemTotalGB          = $totalMemGB
                MemFreeGB           = $freeMemGB
                DrivesSummary       = $drivesSumCsv
                OverallStatus       = $overallStatus
            })
        } else {
            $out.Add("  NOT FOUND")
        }
    #endregion CS Admin

    #region Log tail console output
        $out.Add("")
        $out.Add("Log File Analysis (last $LogTailLines lines, errors/warnings only):")
        foreach ($tail in $logTails) {
            $out.Add("  -- $($tail.Label) ($($tail.Path)) --")
            if ($tail.ParseError) {
                $out.Add("    [WARN] $($tail.ParseError)")
            } elseif ($tail.Lines.Count -eq 0) {
                $out.Add("    No errors or warnings found in last $LogTailLines lines")
            } else {
                foreach ($line in $tail.Lines) {
                    $prefix = switch ($line.Severity) {
                        "CRITICAL" { "[CRITICAL]" }
                        "ERROR"    { "[ERROR]   " }
                        default    { "[WARN]    " }
                    }
                    $out.Add("    $prefix $($line.Text)")
                }
            }
        }
    #endregion Log tail console output

    #region Windows event log console
        if ($eventLines.Count -gt 0) {
            $out.Add("")
            $out.Add("Recent Application Log Events (last 24h, Tomcat/CS related):")
            foreach ($line in $eventLines) { $out.Add("  $line") }
            $overallStatus = Set-OverallStatus $overallStatus "WARN"
        }
    #endregion Windows event log console

    } finally {
        Remove-PSSession $session -ErrorAction SilentlyContinue
    }

    $instanceResults.Add([PSCustomObject]@{
        ComputerName     = $ComputerName
        GroupName        = $GroupName
        Output           = $out
        CsvRows          = $csvRows
        OverallStatus    = $overallStatus
        TomcatVersion    = $tomcatVersion
        EventLines       = $eventLines
        DriveErrors      = $driveErrors
        DriveWarnings    = $driveWarnings
        InformantResults = $allInformant
        GcCollector      = $gcCollector
        GcWarnings       = $gcWarnings
        GcRecommend      = $gcRecommend
        MemPct           = $memPct
        CpuAvg           = $cpuAvg
        MemUsedGB        = $usedMemGB
        MemTotalGB       = $totalMemGB
        MemFreeGB        = $freeMemGB
        DrivesSummary    = $drivesSumCsv
        Uptime           = $uptimeStr
        JobLog           = $jobLog
        CertResults      = $certResults
        GcStats          = $gcStats
        LogTails         = $logTails
    })
    return $instanceResults
}
#endregion Job scriptblock

#region Main
Write-Host "Running as : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor Cyan
if (-not $elevated) {
    Write-Host "WARNING: Not running as Administrator -- some operations may be limited." -ForegroundColor Yellow
}

$startTime = Get-Date
Write-Log "Remote Service Status Check v4.8 (WinRM)" -Color Cyan
Write-Log "Started  : $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Gray
Write-Log "Log file : $logFile" -Color Gray
Write-Log ""

$jobs = [System.Collections.Generic.List[hashtable]]::new()
foreach ($group in $serverGroups.Keys) {
    foreach ($server in $serverGroups[$group]) {
        while ((Get-Job -State Running).Count -ge $MaxParallelJobs) { Start-Sleep -Milliseconds 200 }
        $j = Start-Job -ScriptBlock $checkServicesScript `
                 -ArgumentList $server, $group, $webTimeoutSec, $InformantWarnMs,
                               $EventLogCount, ($AutoRestartStopped.IsPresent),
                               $LogTailLines, $CertWarnDays, $CertCritDays,
                               $GcPauseWarnMs, $GcFreqWarnPerHour, $CsLogRoot,
                               $GcTailLines, $WinRmOpenTimeoutMs, $WinRmOperationTimeoutMs,
                               $ScFailureResetSec, $ScRestartDelayMs, $LogLineTruncateChars,
                               ($CsUseHttps.IsPresent),
                               $WinRmRetryCount, $WinRmRetryDelaySec,
                               $DriveWarnPct, $DriveCritPct,
                               $InformantComponents,
                               $DriveCritFreeGB,
                               $Credential
        $jobs.Add(@{ Job=$j; Server=$server; Group=$group })
        Write-Log "Queued: [$group] $server" -Color Gray
    }
}

Write-Log "Checking $serverCount server(s) -- max $MaxParallelJobs parallel..." -Color Yellow
# NOTE: WinRM default max concurrent connections per server is 25. If $MaxParallelJobs
# is raised above 10 and other WinRM activity is occurring, you may hit timeout errors.
# Increase gradually and monitor for "WS-Management service cannot complete" errors.

foreach ($entry in $jobs) {
    $finished = $entry.Job | Wait-Job -Timeout $jobTimeoutSec
    if (-not $finished) {
        Write-Log "TIMEOUT: [$($entry.Group)] $($entry.Server)" -Color Red
        Stop-Job   $entry.Job
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
        Add-Content -Path $logFile -Value $result.JobLog -Encoding UTF8
    }
}
#endregion Main

#region Delta detection
$prevData = @{}
$prevCsvs = Get-ChildItem -Path $PSScriptRoot -Filter "ServiceCheck_*.csv" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne (Split-Path $csvFile -Leaf) } |
            Sort-Object LastWriteTime -Descending
if ($prevCsvs) {
    $candidateCsv = $prevCsvs[0]
    $prevRows     = Import-Csv -Path $candidateCsv.FullName -ErrorAction SilentlyContinue
    $requiredCols = @('Server','ServiceName','Status','Version')
    $csvCols      = if ($prevRows) { ($prevRows | Select-Object -First 1).PSObject.Properties.Name } else { @() }
    $missingCols  = $requiredCols | Where-Object { $_ -notin $csvCols }
    $hasMarker    = ($prevRows | Where-Object { $_.ServiceType -eq '_COMPLETE_' }) -ne $null
    if ($missingCols) {
        Write-Log "  [WARN] Previous CSV missing columns ($($missingCols -join ',')) -- skipping delta" -Color Yellow
    } elseif (-not $hasMarker) {
        Write-Log "  [WARN] Previous CSV has no completion marker -- skipping delta" -Color Yellow
    } else {
        foreach ($row in ($prevRows | Where-Object { $_.ServiceType -ne '_COMPLETE_' })) {
            $prevData["$($row.Server)|$($row.ServiceName)"] = $row
        }
        Write-Log "Comparing against: $($candidateCsv.Name)" -Color Gray
    }
}
#endregion Delta detection

#region Console output
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
    if ($QuietOK -and $isClean) {
        Write-Log "  $($result.ComputerName) : OK" -Color Green
        continue
    }

    foreach ($line in $result.Output) {
        $color = "White"
        if     ($line -match "^={3,}|Server\s+:")                                                                { $color = "Cyan"    }
        elseif ($line -match "Zone\s+:|Zone\s*:")                                                                 { $color = "Magenta" }
        elseif ($line -match "Recent Reboot")                                                                     { $color = "Yellow"  }
        elseif ($line -match "Tomcat Service:|Content Server Service|Informant Health|TLS Cert|GC Activ|Log File") { $color = "Yellow" }
        elseif ($line -match "^\s*\[DRIVE_CRITICAL\]")                                                            { $color = "Red"     }
        elseif ($line -match "\[RUNNING\]|\[SUCCESS\]|\[OK\]")                                                    { $color = "Green"   }
        elseif ($line -match "\[STOPPED\]|ERROR:|NOT FOUND|\[FAILURE\]|\[ERROR\]|\[CRITICAL\]")                  { $color = "Red"     }
        elseif ($line -match "\[WARN\]|\[OTHER\]|\[SLOW\]|WARN\s*-")                                             { $color = "Yellow"  }
        elseif ($line -match "\[AUTO-RESTART\]")                                                                  { $color = "Cyan"    }
        elseif ($line -match "Heap|GC|Unexp|CPU|Memory|Drive|Cert|Expiry|Thumbprint|Working Set")                { $color = "Cyan"    }
        elseif ($line -match "Run As:|Restart Config:|Service Uptime:")                                           { $color = "Cyan"    }
        elseif ($line -match "Description:|Display Name:")                                                        { $color = "Gray"    }
        Write-Log $line -Color $color
    }

    if ($hasDelta) {
        Write-Log "  >> Changes on $($result.ComputerName):" -Color Yellow
        foreach ($d in $deltaDetails) { Write-Log "     $d" -Color Yellow }
    }
}
#endregion Console output

#region Zone rollup
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
            Write-Log "    [VERSION MISMATCH] Majority: $majority" -Color Yellow
            foreach ($o in $outliers) { Write-Log "      $($o.Key) : $($o.Value)" -Color Yellow }
        }
    }
}
Write-Log "=============================" -Color Cyan
#endregion Zone rollup

#region CSV export
$allCsvRows = $results | ForEach-Object { $_.CsvRows } | Where-Object { $_ }
if ($allCsvRows) {
    $sentinel = [PSCustomObject]@{
        DateTime            = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Zone                = "_COMPLETE_"
        Server              = "_COMPLETE_"
        ServiceType         = "_COMPLETE_"
        ServiceName         = "_COMPLETE_"
        DisplayName         = ""
        Description         = ""
        Status              = ""
        Version             = ""
        JrePath             = ""
        HeapInitMB          = $null
        HeapMaxMB           = $null
        HeapUsagePct        = $null
        GcCollector         = ""
        GcLoggingEnabled    = $false
        GcCollectionsPerHr  = $null
        GcMaxPauseMs        = $null
        GcAvgPauseMs        = $null
        GcHeapTrendMB       = $null
        OomDetected         = $false
        GcWarnings          = ""
        GcRecommend         = ""
        RunAs               = ""
        ServiceUptime       = ""
        RestartConfig       = ""
        UnexpTerms24h       = $null
        WorkingSetMB        = ""
        ServerUptime        = ""
        RecentReboot        = $false
        CpuPct              = $null
        MemPct              = $null
        MemUsedGB           = $null
        MemTotalGB          = $null
        MemFreeGB           = $null
        DrivesSummary       = ""
        OverallStatus       = ""
    }
    ($allCsvRows + $sentinel) | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Log "CSV : $csvFile" -Color Green
} else {
    Write-Log "No CSV data to export." -Color Yellow
}
#endregion CSV export

#region HTML report
function Build-HtmlReport {
    param(
        [object[]]$Results,
        [string]$PfSection,
        [string]$RunAs,
        [datetime]$StartTime,
        [datetime]$EndTime
    )

    function Get-StatusClass {
        param([string]$s)
        switch ($s) { "OK"{"ok"} "WARN"{"warn"} "CRITICAL"{"crit"} "DOWN"{"crit"} default{"unknown"} }
    }

    $serverSb = [System.Text.StringBuilder]::new()
    $svcSb    = [System.Text.StringBuilder]::new()
    $certSb   = [System.Text.StringBuilder]::new()
    $logSb    = [System.Text.StringBuilder]::new()
    $evtSb    = [System.Text.StringBuilder]::new()

    foreach ($r in ($Results | Sort-Object GroupName, ComputerName)) {
        $sc      = Get-StatusClass $r.OverallStatus
        $csNames = if ($r.CsvRows) {
            ($r.CsvRows | Where-Object { $_.ServiceType -eq "ContentServer" } |
             Select-Object -ExpandProperty ServiceName -Unique) -join ", "
        } else { "N/A" }
        $certSummary = if ($r.CertResults) {
            ($r.CertResults | ForEach-Object {
                if ($_.Error) { "port $($_.Port): ERROR" }
                else { "port $($_.Port): $($_.Expiry) ($($_.DaysLeft)d)" }
            }) -join " | "
        } else { "" }

        # Collect critical/error events for this server from log tails and event lines
        $critEvents = [System.Collections.Generic.List[PSCustomObject]]::new()
        if ($r.LogTails) {
            foreach ($tail in $r.LogTails) {
                foreach ($line in $tail.Lines) {
                    if ($line.Severity -in @("CRITICAL","ERROR")) {
                        $critEvents.Add([PSCustomObject]@{
                            Source   = $tail.Label
                            Severity = $line.Severity
                            Text     = $line.Text
                        })
                    }
                }
            }
        }
        foreach ($evtLine in $r.EventLines) {
            if ($evtLine -match "^\[ERROR\]") {
                $critEvents.Add([PSCustomObject]@{
                    Source   = "Windows Event Log"
                    Severity = "ERROR"
                    Text     = $evtLine
                })
            }
        }
        # Cert critical events — only reported if the port actually responded
        # (CertResults entries are only added when a TLS handshake succeeded or
        # a real TLS error occurred on an open port; ports that simply did not
        # respond produce no entry, so this loop is already naturally guarded.
        # The explicit check on $cert.Error being a connection-refused/timeout
        # message below avoids flagging ports that were never open.)
        foreach ($cert in $r.CertResults) {
            # Skip entirely if the error indicates the port was not open/reachable
            if ($cert.Error -and ($cert.Error -match 'refused|timed out|No connection|actively refused|Unable to connect')) {
                continue
            }
            if ($null -ne $cert.DaysLeft -and $cert.DaysLeft -le $CertCritDays) {
                $critEvents.Add([PSCustomObject]@{
                    Source   = "TLS Certificate (port $($cert.Port))"
                    Severity = "CRITICAL"
                    Text     = "Certificate expires $($cert.Expiry) — $($cert.DaysLeft) days remaining. Subject: $($cert.Subject)"
                })
            }
            if ($cert.Error) {
                $critEvents.Add([PSCustomObject]@{
                    Source   = "TLS Certificate (port $($cert.Port))"
                    Severity = "ERROR"
                    Text     = $cert.Error
                })
            }
        }
        # GC OOM
        if ($r.GcStats -and $r.GcStats.OomFound) {
            $critEvents.Add([PSCustomObject]@{
                Source   = "GC Log (catalina.out)"
                Severity = "CRITICAL"
                Text     = "OutOfMemoryError detected in GC log"
            })
        }

        $hasCritEvents  = $critEvents.Count -gt 0
        $dropdownId     = "crit_" + ($r.ComputerName -replace '[^a-zA-Z0-9]','_')
        $colSpan        = 9  # matches number of columns in server summary table

        [void]$serverSb.Append("<tr class='$sc'>")
        [void]$serverSb.Append("<td>$(HtmlEncode $r.GroupName)</td>")

        # Server name cell — clickable chevron when critical events exist
        if ($hasCritEvents) {
            [void]$serverSb.Append("<td class='server'>")
            [void]$serverSb.Append("<span class='expand-btn' onclick=""toggleCrit('$dropdownId')"" title='Show critical events'>")
            [void]$serverSb.Append("<span class='chevron' id='chv_$dropdownId'>&#9654;</span> ")
            [void]$serverSb.Append("$(HtmlEncode $r.ComputerName)")
            [void]$serverSb.Append("</span></td>")
        } else {
            [void]$serverSb.Append("<td class='server'>$(HtmlEncode $r.ComputerName)</td>")
        }

        [void]$serverSb.Append("<td>$(HtmlEncode $csNames)</td>")
        [void]$serverSb.Append("<td><span class='chip $sc'>$($r.OverallStatus)</span></td>")
        [void]$serverSb.Append("<td>$(HtmlEncode $r.Uptime)</td>")
        [void]$serverSb.Append("<td>$(if ($null -ne $r.CpuAvg) { "$($r.CpuAvg)%" } else { "N/A" })</td>")
        [void]$serverSb.Append("<td>$($r.MemPct)% ($($r.MemUsedGB)/$($r.MemTotalGB) GB)</td>")
        [void]$serverSb.Append("<td>$(HtmlEncode $r.DrivesSummary)</td>")
        [void]$serverSb.Append("<td>$(HtmlEncode $certSummary)</td>")
        [void]$serverSb.Append("</tr>")

        # Dropdown row — hidden by default, toggled by chevron click
        if ($hasCritEvents) {
            [void]$serverSb.Append("<tr class='crit-dropdown-row' id='$dropdownId' style='display:none'>")
            [void]$serverSb.Append("<td colspan='$colSpan' class='crit-dropdown-cell'>")
            [void]$serverSb.Append("<table class='crit-inner-tbl'><thead><tr>")
            [void]$serverSb.Append("<th>Severity</th><th>Source</th><th>Detail</th>")
            [void]$serverSb.Append("</tr></thead><tbody>")
            foreach ($ce in $critEvents) {
                $sevCls = if ($ce.Severity -eq "CRITICAL") { "crit" } else { "warn" }
                [void]$serverSb.Append("<tr>")
                [void]$serverSb.Append("<td><span class='chip $sevCls'>$(HtmlEncode $ce.Severity)</span></td>")
                [void]$serverSb.Append("<td class='crit-source'>$(HtmlEncode $ce.Source)</td>")
                [void]$serverSb.Append("<td class='crit-text'>$(HtmlEncode $ce.Text)</td>")
                [void]$serverSb.Append("</tr>")
            }
            [void]$serverSb.Append("</tbody></table>")
            [void]$serverSb.Append("</td></tr>")
        }

        if ($r.CsvRows) {
            foreach ($row in $r.CsvRows) {
                $sc2 = Get-StatusClass $row.OverallStatus
                $gcCell = if ($row.ServiceType -eq "Tomcat") {
                    $parts = [System.Collections.Generic.List[string]]::new()
                    if ($row.GcCollectionsPerHr)     { $parts.Add("$($row.GcCollectionsPerHr)/hr") }
                    if ($row.GcMaxPauseMs)           { $parts.Add("max $($row.GcMaxPauseMs)ms") }
                    if ($row.OomDetected -eq "True") { $parts.Add("OOM!") }
                    if ($row.HeapUsagePct)           { $parts.Add("heap $($row.HeapUsagePct)%") }
                    $parts -join " | "
                } else { "" }

                # Collect errors specific to this service row
                $svcErrors = [System.Collections.Generic.List[PSCustomObject]]::new()

                # Stopped service
                if ($row.Status -ne "Running") {
                    $svcErrors.Add([PSCustomObject]@{ Severity="CRITICAL"; Source="Service State";  Text="Service is $($row.Status) (expected Running)" })
                }
                # OOM
                if ($row.OomDetected -eq "True") {
                    $svcErrors.Add([PSCustomObject]@{ Severity="CRITICAL"; Source="GC Log";         Text="OutOfMemoryError detected in catalina.out" })
                }
                # GC warnings (pipe-separated string from CSV)
                if ($row.GcWarnings) {
                    foreach ($w in ($row.GcWarnings -split '\s*\|\s*')) {
                        if ($w.Trim()) {
                            $svcErrors.Add([PSCustomObject]@{ Severity="WARN"; Source="GC Config"; Text=$w.Trim() })
                        }
                    }
                }
                # Unexpected terminations
                if ($row.UnexpTerms24h -and [int]$row.UnexpTerms24h -gt 0) {
                    $svcErrors.Add([PSCustomObject]@{ Severity="WARN"; Source="Event Log";
                        Text="$($row.UnexpTerms24h) unexpected termination(s) in last 24 hours" })
                }
                # Log tail errors for this specific service (match by service name in label)
                if ($r.LogTails) {
                    foreach ($tail in $r.LogTails) {
                        # Match catalina.out to Tomcat rows; CS thread logs to their instance name
                        $tailMatchesSvc = ($row.ServiceType -eq "Tomcat" -and $tail.Label -eq "catalina.out") -or
                                          ($row.ServiceType -ne "Tomcat" -and $tail.Label -like "*$($row.ServiceName)*")
                        if (-not $tailMatchesSvc) { continue }
                        foreach ($line in $tail.Lines) {
                            if ($line.Severity -in @("CRITICAL","ERROR")) {
                                $svcErrors.Add([PSCustomObject]@{
                                    Severity = $line.Severity
                                    Source   = $tail.Label
                                    Text     = $line.Text
                                })
                            }
                        }
                    }
                }

                $hasSvcErrors  = $svcErrors.Count -gt 0
                $svcDropId     = "svc_" + ($row.Server -replace '[^a-zA-Z0-9]','_') + "_" + ($row.ServiceName -replace '[^a-zA-Z0-9]','_')
                $svcColSpan    = 11  # matches number of columns in service details table (now includes Instance)

                [void]$svcSb.Append("<tr class='$sc2'>")
                [void]$svcSb.Append("<td>$(HtmlEncode $row.Zone)</td>")

                # Server name cell — clickable chevron when errors exist
                if ($hasSvcErrors) {
                    [void]$svcSb.Append("<td class='server'>")
                    [void]$svcSb.Append("<span class='expand-btn' onclick=""toggleCrit('$svcDropId')"" title='Show service errors'>")
                    [void]$svcSb.Append("<span class='chevron' id='chv_$svcDropId'>&#9654;</span> ")
                    [void]$svcSb.Append("$(HtmlEncode $row.Server)")
                    [void]$svcSb.Append("</span></td>")
                } else {
                    [void]$svcSb.Append("<td class='server'>$(HtmlEncode $row.Server)</td>")
                }

                [void]$svcSb.Append("<td>$(HtmlEncode $csNames)</td>")
                [void]$svcSb.Append("<td>$(HtmlEncode $row.ServiceType)</td>")
                [void]$svcSb.Append("<td>$(HtmlEncode $row.ServiceName)</td>")
                [void]$svcSb.Append("<td><span class='chip $sc2'>$($row.Status)</span></td>")
                [void]$svcSb.Append("<td>$(HtmlEncode $row.ServiceUptime)</td>")
                [void]$svcSb.Append("<td>$($row.UnexpTerms24h)</td>")
                [void]$svcSb.Append("<td>$(HtmlEncode $row.WorkingSetMB)</td>")
                [void]$svcSb.Append("<td>$(HtmlEncode $gcCell)</td>")
                [void]$svcSb.Append("<td>$(HtmlEncode $row.GcWarnings)</td>")
                [void]$svcSb.Append("</tr>")

                # Dropdown error row
                if ($hasSvcErrors) {
                    [void]$svcSb.Append("<tr class='crit-dropdown-row' id='$svcDropId' style='display:none'>")
                    [void]$svcSb.Append("<td colspan='$svcColSpan' class='crit-dropdown-cell'>")
                    [void]$svcSb.Append("<table class='crit-inner-tbl'><thead><tr>")
                    [void]$svcSb.Append("<th>Severity</th><th>Source</th><th>Detail</th>")
                    [void]$svcSb.Append("</tr></thead><tbody>")
                    foreach ($se in $svcErrors) {
                        $sevCls = if ($se.Severity -eq "CRITICAL") { "crit" } else { "warn" }
                        [void]$svcSb.Append("<tr>")
                        [void]$svcSb.Append("<td><span class='chip $sevCls'>$(HtmlEncode $se.Severity)</span></td>")
                        [void]$svcSb.Append("<td class='crit-source'>$(HtmlEncode $se.Source)</td>")
                        [void]$svcSb.Append("<td class='crit-text'>$(HtmlEncode $se.Text)</td>")
                        [void]$svcSb.Append("</tr>")
                    }
                    [void]$svcSb.Append("</tbody></table></td></tr>")
                }
            }
        }

        # Only add to the TLS section if at least one port was active (i.e.
        # CertResults is non-empty — it is only populated for open ports).
        if ($r.CertResults -and $r.CertResults.Count -gt 0) {
            foreach ($cert in $r.CertResults) {
                $sc3 = if ($cert.Error)                           { "warn" }
                       elseif ($cert.DaysLeft -le $CertCritDays) { "crit" }
                       elseif ($cert.DaysLeft -le $CertWarnDays) { "warn" }
                       else { "ok" }
                $statusLabel = if ($cert.Error)                           { "ERROR" }
                               elseif ($cert.DaysLeft -le $CertCritDays) { "EXPIRING" }
                               elseif ($cert.DaysLeft -le $CertWarnDays) { "WARN" }
                               else { "OK" }
                [void]$certSb.Append("<tr class='$sc3'>")
                [void]$certSb.Append("<td class='server'>$(HtmlEncode $r.ComputerName)</td>")
                [void]$certSb.Append("<td>$(HtmlEncode $csNames)</td>")
                [void]$certSb.Append("<td>$($cert.Port)</td>")
                [void]$certSb.Append("<td><span class='chip $sc3'>$statusLabel</span></td>")
                [void]$certSb.Append("<td>$(HtmlEncode $cert.Subject)</td>")
                [void]$certSb.Append("<td>$(HtmlEncode $cert.Expiry)</td>")
                [void]$certSb.Append("<td>$(if ($null -ne $cert.DaysLeft) { $cert.DaysLeft } else { 'N/A' })</td>")
                [void]$certSb.Append("<td>$(HtmlEncode $cert.Issuer)</td>")
                [void]$certSb.Append("<td>$(HtmlEncode $cert.Error)</td>")
                [void]$certSb.Append("</tr>")
            }
        }

        if ($r.LogTails) {
            foreach ($tail in $r.LogTails) {
                foreach ($line in $tail.Lines) {
                    $sc4 = switch ($line.Severity) { "CRITICAL"{"crit"} "ERROR"{"warn"} default{""} }
                    [void]$logSb.Append("<tr class='$sc4'>")
                    [void]$logSb.Append("<td class='server'>$(HtmlEncode $r.ComputerName)</td>")
                    [void]$logSb.Append("<td>$(HtmlEncode $csNames)</td>")
                    [void]$logSb.Append("<td>$(HtmlEncode $tail.Label)</td>")
                    [void]$logSb.Append("<td>$(HtmlEncode $line.Severity)</td>")
                    [void]$logSb.Append("<td style='white-space:normal'>$(HtmlEncode $line.Text)</td>")
                    [void]$logSb.Append("</tr>")
                }
            }
        }

        foreach ($line in $r.EventLines) {
            $cls = if ($line -match "^\[ERROR\]") { "crit" } elseif ($line -match "^\[WARN\]") { "warn" } else { "" }
            [void]$evtSb.Append("<tr class='$cls'>")
            [void]$evtSb.Append("<td class='server'>$(HtmlEncode $r.ComputerName)</td>")
            [void]$evtSb.Append("<td>$(HtmlEncode $csNames)</td>")
            [void]$evtSb.Append("<td>$(HtmlEncode $line)</td>")
            [void]$evtSb.Append("</tr>")
        }
    }

    $dur = $EndTime - $StartTime

    $certSection = if ($certSb.Length -gt 0) {
        "<div class='section'><h2>TLS certificate details</h2><table><thead><tr><th>Server</th><th>Instance</th><th>Port</th><th>Status</th><th>Subject</th><th>Expiry</th><th>Days left</th><th>Issuer</th><th>Error</th></tr></thead><tbody>$($certSb.ToString())</tbody></table></div>"
    } else { "" }

    $logSection = if ($logSb.Length -gt 0) {
        "<div class='section'><h2>Log file errors and warnings</h2><table><thead><tr><th>Server</th><th>Instance</th><th>Log</th><th>Severity</th><th>Message</th></tr></thead><tbody>$($logSb.ToString())</tbody></table></div>"
    } else { "" }

    $evtSection = if ($evtSb.Length -gt 0) {
        "<div class='section'><h2>Windows application log events (Tomcat/CS, last 24h)</h2><table><thead><tr><th>Server</th><th>Instance</th><th>Event</th></tr></thead><tbody>$($evtSb.ToString())</tbody></table></div>"
    } else { "" }

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Service Check v4.8 -- $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))</title>
<style>
  *{box-sizing:border-box}
  body{font-family:Consolas,'Courier New',monospace;font-size:12px;background:#1a1a1a;color:#d4d4d4;margin:0;padding:16px}
  h1{color:#4ec9b0;font-size:16px;font-weight:500;margin:0 0 2px}
  h2{color:#9cdcfe;font-size:11px;font-weight:500;margin:18px 0 6px;border-bottom:1px solid #2d2d2d;padding-bottom:4px;text-transform:uppercase;letter-spacing:.06em}
  .meta{color:#666;font-size:11px;margin-bottom:14px}
  .run-info{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px;padding:8px 12px;background:#222;border-radius:4px;border:0.5px solid #333}
  .run-info span{color:#888;font-size:11px} .run-info strong{color:#ccc}
  table{border-collapse:collapse;width:100%;margin-bottom:4px;font-size:11px}
  th{background:#252526;color:#9cdcfe;text-align:left;padding:5px 8px;border-bottom:0.5px solid #3a3a3a;white-space:nowrap;font-weight:500}
  td{padding:4px 8px;border-bottom:0.5px solid #252526;vertical-align:top;white-space:nowrap}
  tr.ok td{background:#1a251a} tr.warn td{background:#252018} tr.crit td{background:#251e10}
  .chip{display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:500}
  .chip.ok{background:#1e3d1e;color:#4ec9a0} .chip.warn{background:#3d3010;color:#e2c060} .chip.crit{background:#3d2200;color:#ff8c00} .chip.unknown{background:#333;color:#888}
  td.server{font-weight:500;color:#ccc}
  .pf-section{margin-bottom:20px} .pf-title{color:#9cdcfe;font-size:13px;font-weight:500;margin-bottom:4px} .pf-meta{color:#888;font-size:11px;margin-bottom:8px}
  td.pf-ok{color:#4ec9a0} td.pf-fail{font-weight:700} td.pf-server{font-weight:500;white-space:nowrap}
  ul.pf-diag{margin:0;padding-left:14px;color:#e2c060;font-size:10px}
  tr.pf-ok td{background:#1a251a} tr.pf-warn td{background:#252018} tr.pf-crit td{background:#251e10}
  .toggle-row{display:flex;align-items:center;gap:10px;margin-bottom:14px;font-size:11px;color:#888}
  .toggle-track{position:relative;width:28px;height:16px;background:#444;border-radius:8px;cursor:pointer;transition:background .2s;border:0.5px solid #666}
  .toggle-track.on{background:#266226}
  .toggle-knob{position:absolute;top:2px;left:2px;width:10px;height:10px;background:#ccc;border-radius:50%;transition:transform .2s}
  .toggle-track.on .toggle-knob{transform:translateX(12px)}
  .em-only tr:not(.warn):not(.crit) td{opacity:.2}
  .em-only tr:not(.warn):not(.crit) .chip{opacity:.2}
  .section{margin-bottom:20px}
  .expand-btn{cursor:pointer;user-select:none;color:#9cdcfe}
  .expand-btn:hover{color:#4ec9b0}
  .chevron{display:inline-block;font-size:9px;transition:transform .2s;color:#9cdcfe}
  .chevron.open{transform:rotate(90deg)}
  .crit-dropdown-row td{padding:0}
  .crit-dropdown-cell{padding:6px 16px 10px 32px !important;background:#1c1010;border-bottom:1px solid #3a2020}
  .crit-inner-tbl{width:100%;border-collapse:collapse;font-size:11px;margin:0}
  .crit-inner-tbl th{background:#2a1a1a;color:#f47272;padding:4px 8px;font-weight:500;text-align:left;border-bottom:1px solid #3a2020}
  .crit-inner-tbl td{padding:3px 8px;border-bottom:1px solid #251515;background:transparent;white-space:normal}
  .crit-inner-tbl tr:last-child td{border-bottom:none}
  td.crit-source{color:#e2c060;white-space:nowrap;min-width:160px}
  td.crit-text{color:#d4d4d4;word-break:break-word}
</style>
</head>
<body>
<h1>Service Check v4.8</h1>
<div class="meta">$($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))</div>
<div class="run-info">
  <span>Running as: <strong>$(HtmlEncode $RunAs)</strong></span>
  <span>Elevated: <strong>$(if ($elevated) {'YES'} else {'NO'})</strong></span>
  <span>Duration: <strong>$($dur.ToString('mm\:ss'))</strong></span>
  <span>Servers: <strong>$($Results.Count)</strong></span>
  <span>Cert warn: <strong>${CertWarnDays}d</strong></span>
  <span>Cert crit: <strong>${CertCritDays}d</strong></span>
</div>
<div class="toggle-row">
  <div class="toggle-track" id="tog" onclick="toggleMode()"><div class="toggle-knob"></div></div>
  <span id="tog-label">Full view</span>
</div>
$PfSection
<div class="section">
<h2>Server health summary</h2>
<table><thead><tr><th>Zone</th><th>Server</th><th>Instance</th><th>Status</th><th>Uptime</th><th>CPU</th><th>Memory</th><th>Drives</th><th>Certificates</th></tr></thead>
<tbody>$($serverSb.ToString())</tbody></table></div>
<div class="section">
<h2>Service details</h2>
<table><thead><tr><th>Zone</th><th>Server</th><th>Instance</th><th>Type</th><th>Service name</th><th>Status</th><th>Uptime</th><th>Terms 24h</th><th>Working set</th><th>GC stats</th><th>GC warnings</th></tr></thead>
<tbody>$($svcSb.ToString())</tbody></table></div>
$certSection
$logSection
$evtSection
<script>
var em=false;
function toggleMode(){
  em=!em;
  var tbls=document.querySelectorAll('table');
  for(var i=0;i<tbls.length;i++){tbls[i].classList.toggle('em-only',em);}
  document.getElementById('tog').classList.toggle('on',em);
  document.getElementById('tog-label').textContent=em?'Issues only':'Full view';
}
function toggleCrit(id){
  var row=document.getElementById(id);
  var chv=document.getElementById('chv_'+id);
  if(!row) return;
  var visible=row.style.display!=='none';
  row.style.display=visible?'none':'table-row';
  if(chv) chv.classList.toggle('open',!visible);
}
</script>
</body></html>
"@
}

$htmlContent = Build-HtmlReport -Results $results -PfSection $pfHtmlSection `
    -RunAs $runningAs -StartTime $startTime -EndTime (Get-Date)
Set-Content -Path $htmlFile -Value $htmlContent -Encoding UTF8
Write-Log "HTML: $htmlFile" -Color Green
#endregion HTML report

#region Alerts
$issueRows = $allCsvRows | Where-Object {
    $_.OverallStatus -in @("DOWN","CRITICAL") -and $_.ServiceType -ne '_COMPLETE_'
}
if ($issueRows) {
    $alertSb = [System.Text.StringBuilder]::new()
    foreach ($_ in $issueRows) {
        $bg = if ($_.OverallStatus -eq "DOWN") { "#2e1a1a" } else { "#3a1a1a" }
        [void]$alertSb.Append("<tr style='background:$bg'>")
        [void]$alertSb.Append("<td style='padding:4px 8px'>$($_.OverallStatus)</td>")
        [void]$alertSb.Append("<td style='padding:4px 8px'>$(HtmlEncode $_.Zone)</td>")
        [void]$alertSb.Append("<td style='padding:4px 8px'>$(HtmlEncode $_.Server)</td>")
        [void]$alertSb.Append("<td style='padding:4px 8px'>$(HtmlEncode $_.ServiceType)</td>")
        [void]$alertSb.Append("<td style='padding:4px 8px'>$(HtmlEncode $_.ServiceName)</td>")
        [void]$alertSb.Append("<td style='padding:4px 8px'>$(HtmlEncode $_.Status)</td>")
        [void]$alertSb.Append("</tr>")
    }

    $htmlBody = @"
<html><body style='font-family:Consolas,monospace;font-size:13px;background:#1e1e1e;color:#d4d4d4;padding:16px'>
<h2 style='color:#ff8c00'>Service Check Alert: $($issueRows.Count) issue(s) detected</h2>
<p style='color:#888'>Run: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))</p>
<table style='border-collapse:collapse;width:100%;font-size:12px'>
  <thead><tr style='background:#252526'>
    <th style='padding:6px 8px;color:#9cdcfe;text-align:left'>Severity</th>
    <th style='padding:6px 8px;color:#9cdcfe;text-align:left'>Zone</th>
    <th style='padding:6px 8px;color:#9cdcfe;text-align:left'>Server</th>
    <th style='padding:6px 8px;color:#9cdcfe;text-align:left'>Service type</th>
    <th style='padding:6px 8px;color:#9cdcfe;text-align:left'>Service name</th>
    <th style='padding:6px 8px;color:#9cdcfe;text-align:left'>State</th>
  </tr></thead>
  <tbody>$($alertSb.ToString())</tbody>
</table>
<p style='color:#888;font-size:11px'>Full report: $htmlFile</p>
</body></html>
"@

    $plainBody = ($issueRows | ForEach-Object {
        "[$($_.OverallStatus)] $($_.Zone) / $($_.Server) - $($_.ServiceType) ($($_.ServiceName)): $($_.Status)"
    }) -join "`n"

    try {
        $msg        = New-Object System.Net.Mail.MailMessage
        $msg.From   = $EmailFrom
        $msg.To.Add($EmailTo)
        $msg.Subject    = "Service Check Alert: $($issueRows.Count) issue(s) detected"
        $msg.Body       = $htmlBody
        $msg.IsBodyHtml = $true

        $smtp             = New-Object System.Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
        $smtp.EnableSsl   = $SmtpUseSsl.IsPresent
        $smtp.DeliveryMethod = [System.Net.Mail.SmtpDeliveryMethod]::Network

        if ($SmtpCredential) {
            $smtp.Credentials = $SmtpCredential.GetNetworkCredential()
        } else {
            $smtp.UseDefaultCredentials = $true
        }

        $smtp.Send($msg)
        $msg.Dispose()
        Write-Log "Alert email sent to $EmailTo" -Color Green
    } catch { Write-Log "Failed to send alert email: $_" -Color Red }

    if ($TeamsWebhookUrl) {
        Send-TeamsAlert -WebhookUrl $TeamsWebhookUrl `
            -Title "Service Check Alert: $($issueRows.Count) issue(s)" -Body $plainBody
        Write-Log "Teams alert sent." -Color Green
    }
}
#endregion Alerts

$endTime = Get-Date
$dur     = $endTime - $startTime
Write-Log ""
Write-Log "========================================" -Color Cyan
Write-Log "Completed : $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Cyan
Write-Log "Duration  : $($dur.ToString('mm\:ss'))" -Color Cyan
Write-Log "========================================" -Color Cyan
Write-Log "Log  : $logFile" -Color Green
Write-Log "CSV  : $csvFile" -Color Green
Write-Log "HTML : $htmlFile" -Color Green

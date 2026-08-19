# Send-LogsToHEC.ps1  — Windows -> Splunk HEC log shipper
# Replaces the Splunk Universal Forwarder (unsupported on Windows ARM).
# Reads new Windows event-log entries, serialises to JSON, posts to Splunk HEC.
# Runs as a scheduled task (every 1 minute) under SYSTEM.
#
# SECURITY: Replace the placeholder values below before use.
# Never commit real tokens or passwords to version control.

# ================== CONFIG — EDIT THESE ==================
$SplunkIP = "YOUR_SPLUNK_IP"          # e.g. 10.211.55.13
$Token    = "YOUR_HEC_TOKEN_HERE"     # HEC token from Splunk
# ========================================================

$HecPort     = 8088
$BookmarkDir = "C:\SOC\bookmarks"
New-Item -ItemType Directory -Force -Path $BookmarkDir | Out-Null

# Accept Splunk self-signed cert (lab only) — Windows PowerShell 5.1
add-type @"
using System.Net;using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicyV2:ICertificatePolicy{
 public bool CheckValidationResult(ServicePoint s,X509Certificate c,WebRequest r,int p){return true;}}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicyV2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$uri = "https://$SplunkIP`:$HecPort/services/collector/event"
$epochStart = Get-Date "1970-01-01 00:00:00Z"

function Ship($LogName,$IndexName){
  $safe = $LogName -replace '[\\/:]','_'
  $bm   = Join-Path $BookmarkDir $safe
  $last = if(Test-Path $bm){ [int64](Get-Content $bm) } else { 0 }
  try {
    $events = Get-WinEvent -LogName $LogName -MaxEvents 5000 -ErrorAction Stop |
              Where-Object { $_.RecordId -gt $last } | Sort-Object RecordId
  } catch { Write-Host "$LogName : cannot read"; return }
  if(-not $events){ Write-Host "$LogName : nothing new"; return }
  $sent = 0; $maxRid = $last
  foreach($e in $events){
    # correct UTC-epoch timestamp so Splunk indexes events at the right time
    $epoch = [int][double]::Parse((($e.TimeCreated.ToUniversalTime()) - $epochStart).TotalSeconds)
    $data = @{ EventCode=$e.Id; Computer=$e.MachineName; Channel=$LogName; Message=$e.Message }
    try { $x=[xml]$e.ToXml(); foreach($d in $x.Event.EventData.Data){ if($d.Name){ $data[$d.Name]=$d.'#text' } } } catch {}
    $payload = @{ time=$epoch; host=$env:COMPUTERNAME; source=$LogName; sourcetype="_json"; index=$IndexName; event=$data } | ConvertTo-Json -Depth 6 -Compress
    try {
      $r = Invoke-RestMethod -Uri $uri -Method Post -Headers @{Authorization="Splunk $Token"} -Body $payload -ContentType 'application/json'
      if($r.code -eq 0){ $sent++; if($e.RecordId -gt $maxRid){ $maxRid = $e.RecordId } }
    } catch {}
  }
  if($maxRid -gt $last){ $maxRid | Set-Content $bm }
  Write-Host "$LogName -> $IndexName : sent $sent"
}

Ship "Security" "windows_security"
Ship "Microsoft-Windows-Sysmon/Operational" "windows_sysmon"
Ship "System" "windows_security"
Ship "Microsoft-Windows-Windows Defender/Operational" "windows_security"

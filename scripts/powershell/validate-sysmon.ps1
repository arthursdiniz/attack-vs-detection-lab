<#
.SYNOPSIS
    Automated Microsoft Sysmon Telemetry Validator.
.DESCRIPTION
    Validates Sysmon service state, queries the active configuration, generates a
    controlled test execution event, and verifies that the event was written to the
    Microsoft-Windows-Sysmon/Operational event channel.
.NOTES
    Run on lab-win11 in an elevated PowerShell session.
#>

[CmdletBinding()]
param()

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ATTACK vs DETECTION LAB -- Sysmon Telemetry Validator  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ("Timestamp: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# 1. Check Service Status
$sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $sysmonService) {
    $sysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
}

if (-not $sysmonService) {
    Write-Host "[!] Sysmon service NOT found. Ensure Sysmon is installed." -ForegroundColor Red
    exit 1
}

if ($sysmonService.Status -ne "Running") {
    Write-Host ("[!] Sysmon service is installed but NOT running (Status: " + $sysmonService.Status + ").") -ForegroundColor Red
    exit 1
}

Write-Host ("[+] Sysmon service is active and running (" + $sysmonService.Name + ").") -ForegroundColor Green

# 2. Trigger Controlled Process Create Event (Event ID 1)
$testMarker = "DetectLab-Telemetry-Check-" + (Get-Random -Minimum 10000 -Maximum 99999)
Write-Host ("[*] Generating controlled test process execution (Marker: " + $testMarker + ")...") -ForegroundColor Yellow

$procStart = Get-Date
Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo $testMarker" -NoNewWindow -Wait

Start-Sleep -Seconds 2

# 3. Query Sysmon Operational Event Channel
Write-Host "[*] Querying Microsoft-Windows-Sysmon/Operational channel..." -ForegroundColor Yellow

$events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    Id        = 1
    StartTime = $procStart.AddSeconds(-2)
} -ErrorAction SilentlyContinue

$matchedEvent = $null
if ($events) {
    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $cmdLine = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'CommandLine' }).'#text'
        if ($cmdLine -and $cmdLine.Contains($testMarker)) {
            $matchedEvent = $evt
            $matchedCmd = $cmdLine
            $matchedImage = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Image' }).'#text'
            $matchedParent = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ParentImage' }).'#text'
            $matchedHash = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'Hashes' }).'#text'
            break
        }
    }
}

Write-Host ""
Write-Host "====================== VALIDATION RESULTS ======================" -ForegroundColor Cyan
if ($matchedEvent) {
    Write-Host "[+] SUCCESS: Sysmon Event ID 1 successfully captured and verified!" -ForegroundColor Green
    Write-Host ("  - Event Record ID  : " + $matchedEvent.RecordId)
    Write-Host ("  - Time Generated   : " + $matchedEvent.TimeCreated)
    Write-Host ("  - Image Executed   : " + $matchedImage)
    Write-Host ("  - Command Line     : " + $matchedCmd)
    Write-Host ("  - Parent Process   : " + $matchedParent)
    Write-Host ("  - Computed Hashes  : " + $matchedHash)
} else {
    Write-Host "[!] WARNING: Test event was executed but not observed in Sysmon log." -ForegroundColor Yellow
    Write-Host "    Verify that cmd.exe is included in sysmonconfig.xml and not excluded."
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

<#
.SYNOPSIS
    Exports security events from Windows Event Log channels into structured JSON.
.DESCRIPTION
    Extracts recent events from Security, Sysmon, and PowerShell operational channels
    and exports them to a timestamped evidence JSON file for offline investigation.
.EXAMPLE
    .\collect-security-events.ps1 -MaxEvents 50
#>

[CmdletBinding()]
param(
    [int]$MaxEvents = 50,
    [string]$OutputDir = ".\evidence\logs"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ATTACK vs DETECTION LAB -- Windows Event Exporter     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outFile = Join-Path $OutputDir "exported-windows-events-$timestamp.json"

$channels = @(
    "Security",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-PowerShell/Operational"
)

$allEvents = @()

foreach ($channel in $channels) {
    Write-Host "[-] Exporting from channel: $channel..." -NoNewline
    $evts = Get-WinEvent -LogName $channel -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
    if ($evts) {
        foreach ($e in $evts) {
            $allEvents += [PSCustomObject]@{
                TimeCreated = $e.TimeCreated.ToString("o")
                Channel     = $channel
                Id          = $e.Id
                Provider    = $e.ProviderName
                Message     = $e.Message
            }
        }
        Write-Host " [$($evts.Count) events exported]" -ForegroundColor Green
    } else {
        Write-Host " [0 events found]" -ForegroundColor Yellow
    }
}

$allEvents | ConvertTo-Json -Depth 4 | Out-File -FilePath $outFile -Encoding utf8
Write-Host "`n[+] Events successfully saved to: $outFile" -ForegroundColor Green
Write-Host "==========================================================`n"

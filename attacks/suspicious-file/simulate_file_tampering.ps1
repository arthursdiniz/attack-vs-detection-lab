<#
.SYNOPSIS
    Scenario: INC-004 - File Integrity Monitoring (FIM) Simulation (Windows)
.DESCRIPTION
    Creates a controlled configuration file in C:\LabStaging\, records its original cryptographic
    hash, performs an unauthorized modification, and allows the Wazuh Syscheck engine to detect
    the delta (MD5, SHA256, timestamp, file size).
.NOTES
    Run on lab-win11 in an elevated PowerShell session.
#>

[CmdletBinding()]
param()

$stagingDir = "C:\LabStaging"
$targetFile = "$stagingDir\sensitive-config.txt"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ATTACK vs DETECTION LAB -- INC-004 Windows FIM Test   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ("Timestamp: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# Ensure Staging directory exists
if (-not (Test-Path $stagingDir)) {
    New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
    Write-Host "[+] Created staging directory: $stagingDir" -ForegroundColor Green
}

# 1. Baseline File Creation
Write-Host "[*] Creating baseline sensitive configuration file..." -ForegroundColor Yellow
$baselineContent = @"
# Lab Staging Configuration Baseline
ENVIRONMENT=PRODUCTION
AUTH_BACKEND=ACTIVE_DIRECTORY
ADMIN_BYPASS=FALSE
API_TOKEN=8f3c7e192a0d4b68
"@
$baselineContent | Out-File -FilePath $targetFile -Encoding utf8 -Force

# Calculate Baseline Hash
$beforeHash = (Get-FileHash -Path $targetFile -Algorithm SHA256).Hash
$beforeMD5  = (Get-FileHash -Path $targetFile -Algorithm MD5).Hash
Write-Host "  [-] File Created      : $targetFile"
Write-Host "  [-] Baseline SHA256   : $beforeHash" -ForegroundColor Green
Write-Host "  [-] Baseline MD5      : $beforeMD5" -ForegroundColor Green

Write-Host "[*] Allowing Wazuh Syscheck to baseline file (waiting 10s)..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# 2. Controlled Malicious Tampering
Write-Host "[*] Simulating unauthorized modification (adversary tampering)..." -ForegroundColor Yellow
$tamperedContent = @"
# Lab Staging Configuration Baseline - TAMPERED BY ADVERSARY
ENVIRONMENT=PRODUCTION
AUTH_BACKEND=ACTIVE_DIRECTORY
ADMIN_BYPASS=TRUE
API_TOKEN=BACKDOOR_TOKEN_COMPROMISED_9999
"@
$tamperedContent | Out-File -FilePath $targetFile -Encoding utf8 -Force

# Calculate Post-Tampering Hash
$afterHash = (Get-FileHash -Path $targetFile -Algorithm SHA256).Hash
$afterMD5  = (Get-FileHash -Path $targetFile -Algorithm MD5).Hash
Write-Host "  [-] File Tampered     : $targetFile"
Write-Host "  [-] Modified SHA256   : $afterHash" -ForegroundColor Red
Write-Host "  [-] Modified MD5      : $afterMD5" -ForegroundColor Red

Write-Host "`n====================== FIM TEST SUMMARY ======================" -ForegroundColor Cyan
Write-Host "Target Path         : $targetFile"
Write-Host "SHA256 Before       : $beforeHash"
Write-Host "SHA256 After        : $afterHash"
Write-Host "Status              : Modification successfully executed."
Write-Host "Expected Detection  : Wazuh Syscheck Alert (Rule 550 / Integrity Checksum Changed)"
Write-Host "==============================================================`n"

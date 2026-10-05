<#
.SYNOPSIS
    Scenario: INC-003 - Controlled Account Creation & Group Promotion Simulator
.DESCRIPTION
    Simulates the adversary technique of creating a backdoor local user account (T1136.001)
    and rapidly elevating its privileges by adding it to the local Administrators security
    group (T1098), generating Windows Event IDs 4720, 4732, and Sysmon Event ID 1.
.NOTES
    Must be executed in an elevated PowerShell session on lab-win11.
    Performs automatic cleanup after simulation.
#>

[CmdletBinding()]
param(
    [string]$TargetUsername = "lab-backdoor",
    [string]$TargetPassword = "LabSecurePassword#2024"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ATTACK vs DETECTION LAB -- INC-003 Account Tampering   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ("Timestamp: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# Verify Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[!] Error: This script requires administrative privileges. Please run as Administrator."
    exit 1
}

# 1. Step 1: Create Local Account (Event ID 4720 / T1136.001)
Write-Host "[*] [Step 1] Creating local backdoor account '$TargetUsername'..." -ForegroundColor Yellow
$createOutput = net user $TargetUsername $TargetPassword /add /comment:"DetectLab Simulated Backdoor" 2>&1
Write-Host ("  [-] net user output: " + $createOutput) -ForegroundColor Green
Write-Host "  [-] Event ID 4720 (User Account Created) generated." -ForegroundColor Green

Write-Host "[*] Pausing 15 seconds before privilege escalation..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# 2. Step 2: Add Account to Local Administrators Group (Event ID 4732 / T1098)
Write-Host "[*] [Step 2] Elevating account: Adding '$TargetUsername' to Administrators group..." -ForegroundColor Yellow
$elevateOutput = net localgroup Administrators $TargetUsername /add 2>&1
Write-Host ("  [-] net localgroup output: " + $elevateOutput) -ForegroundColor Green
Write-Host "  [-] Event ID 4732 (Member Added to Local Security Group) generated." -ForegroundColor Green

Write-Host "[*] Pausing 10 seconds to allow SIEM correlation rule 100022 to evaluate..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# 3. Step 3: Cleanup / Delete Test Account (Event ID 4726)
Write-Host "[*] [Step 3] Cleaning up: Deleting temporary account '$TargetUsername'..." -ForegroundColor Yellow
$deleteOutput = net user $TargetUsername /delete 2>&1
Write-Host ("  [-] net user delete output: " + $deleteOutput) -ForegroundColor Green
Write-Host "  [-] Event ID 4726 (User Account Deleted) generated." -ForegroundColor Green

Write-Host "`n====================== SIMULATION COMPLETE ======================" -ForegroundColor Cyan
Write-Host "[+] Controlled account tampering sequence completed successfully."
Write-Host "    Expected Alert: Wazuh Rule 100022 (Correlation: User Created -> Admin in <120s)."
Write-Host "=================================================================`n"

<#
.SYNOPSIS
    Automated Windows Telemetry and Audit Baseline Configuration.
.DESCRIPTION
    Applies Advanced Windows Audit Policies (auditpol), enables Command Line in Process
    Creation (Event ID 4688), enables PowerShell Script Block Logging (Event ID 4104),
    and validates telemetry configuration for the Attack vs Detection Lab.
.NOTES
    Must be executed in an elevated PowerShell session (Run as Administrator) on lab-win11.
#>

[CmdletBinding()]
param()

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ATTACK vs DETECTION LAB -- Windows Telemetry Setup    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Verify Administrative Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[!] This script must be run as Administrator! Please re-launch PowerShell as Administrator."
    exit 1
}

Write-Host "[+] Confirmed administrative privileges." -ForegroundColor Green

# 2. Configure Advanced Audit Policies via auditpol
Write-Host "[*] Applying Advanced Audit Policies (auditpol)..." -ForegroundColor Yellow

$auditPolicies = @(
    @{ Category = "Logon/Logoff"; Subcategory = "Logon"; Flags = "/success:enable /failure:enable" },
    @{ Category = "Logon/Logoff"; Subcategory = "Other Logon/Logoff Events"; Flags = "/success:enable /failure:enable" },
    @{ Category = "Account Management"; Subcategory = "User Account Management"; Flags = "/success:enable /failure:enable" },
    @{ Category = "Account Management"; Subcategory = "Security Group Management"; Flags = "/success:enable /failure:enable" },
    @{ Category = "Detailed Tracking"; Subcategory = "Process Creation"; Flags = "/success:enable /failure:disable" }
)

foreach ($policy in $auditPolicies) {
    $cmd = "auditpol /set /subcategory:`"$($policy.Subcategory)`" $($policy.Flags)"
    Write-Host "  [-] Setting: $($policy.Subcategory)..." -NoNewline
    Invoke-Expression $cmd | Out-Null
    Write-Host " [OK]" -ForegroundColor Green
}

# 3. Enable Command Line Inclusion in Event ID 4688
Write-Host "[*] Enabling Command Line Logging for Process Creation..." -ForegroundColor Yellow
$auditRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $auditRegPath)) {
    New-Item -Path $auditRegPath -Force | Out-Null
}
Set-ItemProperty -Path $auditRegPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
Write-Host "  [-] Registry key 'ProcessCreationIncludeCmdLine_Enabled' set to 1. [OK]" -ForegroundColor Green

# 4. Enable PowerShell Script Block Logging (Event ID 4104)
Write-Host "[*] Enabling PowerShell Script Block Logging..." -ForegroundColor Yellow
$psScriptBlockPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psScriptBlockPath)) {
    New-Item -Path $psScriptBlockPath -Force | Out-Null
}
Set-ItemProperty -Path $psScriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
Write-Host "  [-] Registry key 'EnableScriptBlockLogging' set to 1. [OK]" -ForegroundColor Green

# 5. Enable PowerShell Module Logging
Write-Host "[*] Enabling PowerShell Module Logging..." -ForegroundColor Yellow
$psModuleLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $psModuleLoggingPath)) {
    New-Item -Path $psModuleLoggingPath -Force | Out-Null
}
Set-ItemProperty -Path $psModuleLoggingPath -Name "EnableModuleLogging" -Value 1 -Type DWord -Force

$moduleNamesPath = "$psModuleLoggingPath\ModuleNames"
if (-not (Test-Path $moduleNamesPath)) {
    New-Item -Path $moduleNamesPath -Force | Out-Null
}
Set-ItemProperty -Path $moduleNamesPath -Name "*" -Value "*" -Type String -Force
Write-Host "  [-] PowerShell Module Logging enabled for all modules (*). [OK]" -ForegroundColor Green

# 6. Verification Summary
Write-Host "`n====================== AUDIT STATUS VERIFICATION ======================" -ForegroundColor Cyan
Write-Host "Process Creation Policy:"
auditpol /get /subcategory:"Process Creation"
Write-Host "Logon Policy:"
auditpol /get /subcategory:"Logon"
Write-Host "User Account Management Policy:"
auditpol /get /subcategory:"User Account Management"

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "[+] Windows Endpoint Telemetry Configuration Completed Successfully!" -ForegroundColor Green
Write-Host "========================================================================`n"

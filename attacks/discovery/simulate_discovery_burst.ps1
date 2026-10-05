<#
.SYNOPSIS
    Scenario: INC-005 - Suspicious System Discovery Burst Simulator
.DESCRIPTION
    Simulates adversary situational awareness / discovery tradecraft by executing a rapid
    sequence of standard Windows enumeration commands (whoami, net, ipconfig, netstat, tasklist,
    systeminfo) within a tight 20-second window to trigger behavioral burst correlation.
.NOTES
    Safe for educational execution on lab-win11.
#>

[CmdletBinding()]
param()

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ATTACK vs DETECTION LAB -- INC-005 Discovery Burst     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ("Timestamp: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Host "Target Host: lab-win11 (192.168.56.20)`n"

$discoveryCommands = @(
    @{ Name = "whoami.exe";   Args = "/all";          MITRE = "T1087.001 - Account Discovery" },
    @{ Name = "net.exe";      Args = "user";          MITRE = "T1087.001 - Account Discovery" },
    @{ Name = "net.exe";      Args = "localgroup";    MITRE = "T1087.001 - Group Discovery" },
    @{ Name = "ipconfig.exe"; Args = "/all";          MITRE = "T1016 - Network Config Discovery" },
    @{ Name = "netstat.exe";  Args = "-ano";          MITRE = "T1049 - Network Connection Discovery" },
    @{ Name = "route.exe";    Args = "print";         MITRE = "T1016 - Routing Table Discovery" },
    @{ Name = "tasklist.exe"; Args = "/v";            MITRE = "T1057 - Process Discovery" },
    @{ Name = "systeminfo.exe"; Args = "";            MITRE = "T1082 - System Info Discovery" }
)

Write-Host "[*] Initiating rapid discovery sequence (burst execution < 25s)..." -ForegroundColor Yellow

$startTime = [System.Diagnostics.Stopwatch]::StartNew()
$count = 0

foreach ($cmd in $discoveryCommands) {
    $count++
    Write-Host ("  [$count/$($discoveryCommands.Count)] Executing " + $cmd.Name + " " + $cmd.Args + " (" + $cmd.MITRE + ")...") -NoNewline
    Start-Process -FilePath $cmd.Name -ArgumentList $cmd.Args -NoNewWindow -Wait
    Write-Host " [OK]" -ForegroundColor Green
    Start-Sleep -Milliseconds 500
}

$startTime.Stop()
$elapsedSeconds = [Math]::Round($startTime.Elapsed.TotalSeconds, 2)

Write-Host "`n====================== DISCOVERY SUMMARY ======================" -ForegroundColor Cyan
Write-Host "Commands Executed   : $count"
Write-Host "Total Burst Duration: $elapsedSeconds seconds"
Write-Host "Rate                : $([Math]::Round($count / $elapsedSeconds, 2)) commands/sec"
Write-Host "Expected Detection  : Wazuh Rule 100041 (>=5 discovery commands in <30s)"
Write-Host "==============================================================`n"

<#
.SYNOPSIS
    Automated network and service validation script for the Attack vs Detection Lab.
.DESCRIPTION
    Validates ICMP connectivity and required service ports across all virtual machines
    on the isolated lab subnet (192.168.56.0/24).
.EXAMPLE
    .\validate-network.ps1
#>

[CmdletBinding()]
param(
    [string]$SubnetPrefix = "192.168.56"
)

$targetSubnet = $SubnetPrefix + ".0/24"
$attackerIp   = $SubnetPrefix + ".10"
$win11Ip      = $SubnetPrefix + ".20"
$ubuntuIp     = $SubnetPrefix + ".30"
$wazuhIp      = $SubnetPrefix + ".40"

$Nodes = @(
    [PSCustomObject]@{ Hostname = "lab-attacker"; IP = $attackerIp; Role = "Attacker (Kali)"; Ports = @() },
    [PSCustomObject]@{ Hostname = "lab-win11";    IP = $win11Ip;    Role = "Victim 01 (Win11)"; Ports = @(3389, 445) },
    [PSCustomObject]@{ Hostname = "lab-ubuntu";   IP = $ubuntuIp;   Role = "Victim 02 (Ubuntu)"; Ports = @(22) },
    [PSCustomObject]@{ Hostname = "lab-wazuh";    IP = $wazuhIp;    Role = "SIEM (Wazuh)"; Ports = @(443, 1514, 1515) }
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   ATTACK vs DETECTION LAB -- Network Verification Suite   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ("Timestamp: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Write-Host ("Target Subnet: " + $targetSubnet)
Write-Host ""

$Results = @()

foreach ($Node in $Nodes) {
    Write-Host ("[-] Testing " + $Node.Hostname + " (" + $Node.IP + ") - " + $Node.Role + "...") -NoNewline
    
    # 1. Test ICMP Reachability
    $PingResult = Test-Connection -ComputerName $Node.IP -Count 1 -Quiet -ErrorAction SilentlyContinue
    $PingStatus = if ($PingResult) { "REACHABLE" } else { "UNREACHABLE" }
    
    if ($PingResult) {
        Write-Host " [PING OK]" -ForegroundColor Green
    } else {
        Write-Host " [PING FAILED]" -ForegroundColor Yellow
    }

    # 2. Test Critical Ports
    $PortResults = @()
    foreach ($Port in $Node.Ports) {
        $TcpTest = Test-NetConnection -ComputerName $Node.IP -Port $Port -WarningAction SilentlyContinue
        $Status = if ($TcpTest.TcpTestSucceeded) { "OPEN" } else { "CLOSED/FILTERED" }
        $PortResults += ("$Port/TCP: " + $Status)
    }

    $PortsSummary = if ($PortResults.Count -gt 0) { ($PortResults -join ", ") } else { "N/A" }

    $Results += [PSCustomObject]@{
        Hostname    = $Node.Hostname
        IPAddress   = $Node.IP
        Role        = $Node.Role
        ICMPStatus  = $PingStatus
        OpenPorts   = $PortsSummary
    }
}

Write-Host ""
Write-Host "====================== SUMMARY REPORT ======================" -ForegroundColor Cyan
$Results | Format-Table -AutoSize -Property Hostname, IPAddress, Role, ICMPStatus, OpenPorts

$FailedPings = $Results | Where-Object { $_.ICMPStatus -eq "UNREACHABLE" }
if ($FailedPings.Count -gt 0) {
    Write-Host ("[!] Warning: " + $FailedPings.Count + " node(s) failed ICMP ping. Verify VM execution status, Host-Only binding, or firewall.") -ForegroundColor Yellow
} else {
    Write-Host "[+] All lab nodes successfully answered ICMP ping requests!" -ForegroundColor Green
}
Write-Host "============================================================"
Write-Host ""

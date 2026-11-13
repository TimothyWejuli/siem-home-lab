<#
.SYNOPSIS
    Checks whether a Windows endpoint can reach the Wazuh manager and whether the local agent is healthy.
.DESCRIPTION
    Separates network problems (ports blocked or wrong IP) from agent problems (not enrolled,
    wrong manager address). This is the check that isolated the "agent running but 0 agents" issue.
.EXAMPLE
    .\Test-WazuhConnectivity.ps1 -ManagerIP 192.168.0.44
#>
param(
    [Parameter(Mandatory)]
    [string]$ManagerIP
)

$agentDir = "C:\Program Files (x86)\ossec-agent"

Write-Host "== Network path to $ManagerIP ==" -ForegroundColor Cyan
foreach ($port in 1515, 1514, 443) {
    $result = Test-NetConnection -ComputerName $ManagerIP -Port $port -WarningAction SilentlyContinue
    $status = if ($result.TcpTestSucceeded) { "OPEN" } else { "BLOCKED / NOT LISTENING" }
    "{0,-6} {1}" -f $port, $status
}

Write-Host "`n== Agent service ==" -ForegroundColor Cyan
Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue | Format-Table Name, Status -AutoSize

Write-Host "== Manager address in ossec.conf ==" -ForegroundColor Cyan
Select-String -Path "$agentDir\ossec.conf" -Pattern '<address>.*</address>' | ForEach-Object { $_.Line.Trim() }

Write-Host "`n== Enrollment key present? ==" -ForegroundColor Cyan
if ((Test-Path "$agentDir\client.keys") -and ((Get-Item "$agentDir\client.keys").Length -gt 0)) {
    "Yes - client.keys exists"
} else {
    "No - agent is not enrolled (run Register-WazuhAgent.ps1)"
}

Write-Host "`n== Last 15 lines of ossec.log ==" -ForegroundColor Cyan
Get-Content "$agentDir\ossec.log" -Tail 15

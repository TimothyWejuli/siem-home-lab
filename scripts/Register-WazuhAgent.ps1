<#
.SYNOPSIS
    Points the Windows Wazuh agent at the manager and enrolls it (or re-enrolls it under a new name).
.DESCRIPTION
    Automates the manual fix used in this lab: set the manager address in ossec.conf,
    enroll with agent-auth.exe on port 1515, and restart the service.
    Use -Reset to delete the existing key first (needed when renaming an agent; remove the
    old agent on the manager with: sudo /var/ossec/bin/manage_agents -r <ID>).
.EXAMPLE
    .\Register-WazuhAgent.ps1 -ManagerIP 192.168.0.44 -AgentName win-laptop-01
.EXAMPLE
    .\Register-WazuhAgent.ps1 -ManagerIP 192.168.0.44 -AgentName win-laptop-01 -Reset
#>
#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory)] [string]$ManagerIP,
    [Parameter(Mandatory)] [string]$AgentName,
    [switch]$Reset
)

$agentDir = "C:\Program Files (x86)\ossec-agent"
$conf     = "$agentDir\ossec.conf"

NET STOP WAZUH

if ($Reset -and (Test-Path "$agentDir\client.keys")) {
    Remove-Item "$agentDir\client.keys" -Force
    Write-Host "Removed old client.keys"
}

$content = Get-Content $conf
$content = $content -replace '<address>.*</address>', "<address>$ManagerIP</address>"
$content = $content -replace '<agent_name>.*</agent_name>', "<agent_name>$AgentName</agent_name>"
Set-Content -Path $conf -Value $content
Write-Host "ossec.conf now points to $ManagerIP"

& "$agentDir\agent-auth.exe" -m $ManagerIP -A $AgentName

NET START WAZUH
Write-Host "Check the dashboard (Endpoints) or run on the server: sudo /var/ossec/bin/agent_control -l"

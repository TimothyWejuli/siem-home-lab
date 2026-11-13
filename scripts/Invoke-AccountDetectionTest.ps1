<#
.SYNOPSIS
    Detection Test 1: local account creation, privilege escalation, failed logons, and deletion.
.DESCRIPTION
    Generates Windows Security events 4720, 4732, 4625, and 4726 with a temporary account so
    you can confirm Wazuh detects them. It scripts the same steps that were run by hand in
    this lab (net user / net localgroup / runas with a wrong password).

    Run ONLY on a lab machine you own. The test account is always deleted at the end.
.EXAMPLE
    .\Invoke-AccountDetectionTest.ps1 -FailedLogons 5
.NOTES
    Dashboard query (Threat Hunting > Events, DQL):
    data.win.system.eventID: (4625 or 4720 or 4732 or 4726)
#>
#Requires -RunAsAdministrator
param(
    [string]$UserName = "testadmin",
    [int]$FailedLogons = 5
)

# Random password so nothing reusable is stored in the repo
$chars    = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%'
$password = -join (1..16 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
$secure   = ConvertTo-SecureString $password -AsPlainText -Force

try {
    Write-Host "[1/4] Creating local user $UserName (Event 4720, T1136.001)"
    New-LocalUser -Name $UserName -Password $secure -Description "Wazuh detection test" | Out-Null

    Write-Host "[2/4] Adding $UserName to Administrators (Event 4732, T1098)"
    Add-LocalGroupMember -Group "Administrators" -Member $UserName

    Write-Host "[3/4] Generating $FailedLogons failed logons (Event 4625, T1110)"
    $bad = New-Object System.Management.Automation.PSCredential(
        "$env:COMPUTERNAME\$UserName", (ConvertTo-SecureString "WrongPassword!1" -AsPlainText -Force))
    for ($i = 1; $i -le $FailedLogons; $i++) {
        try {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c exit" -Credential $bad -WindowStyle Hidden -ErrorAction Stop
        } catch {
            Write-Host "      attempt $i failed as expected"
        }
        Start-Sleep -Seconds 2
    }
}
finally {
    Write-Host "[4/4] Deleting $UserName (Event 4726, T1531)"
    Remove-LocalUser -Name $UserName -ErrorAction SilentlyContinue
}

Write-Host "`nDone. Wait 1-2 minutes, then search the Wazuh dashboard:"
Write-Host "data.win.system.eventID: (4625 or 4720 or 4732 or 4726)"

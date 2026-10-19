<#
.SYNOPSIS
    Registers a Windows scheduled task that runs expirywatch once a day.

.EXAMPLE
    .\scripts\install-schedule.ps1 -ConfigPath C:\expirywatch\config.json -Time 09:00

.EXAMPLE
    .\scripts\install-schedule.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$ExePath = (Join-Path $PSScriptRoot '..\expirywatch.exe'),
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\config.json'),
    [string]$Time = '09:00',
    [string]$TaskName = 'expirywatch',
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'."
    return
}

$exe = (Resolve-Path $ExePath).Path
$config = (Resolve-Path $ConfigPath).Path

$action = New-ScheduledTaskAction -Execute $exe -Argument "--config `"$config`"" -WorkingDirectory (Split-Path $config)
$trigger = New-ScheduledTaskTrigger -Daily -At $Time
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -Description 'Daily certificate and domain expiry check (expirywatch)' -Force | Out-Null

Write-Host "Scheduled '$TaskName' to run daily at $Time using $config."
Write-Host "Run it now with: Start-ScheduledTask -TaskName $TaskName"

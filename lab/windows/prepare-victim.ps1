<#
TechDetechtives VMware lab: prepare the Windows lab endpoint (victim) for detection tests.
Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).

Run in an elevated PowerShell on the LAB VM ONLY (never on a real workstation):
  Set-ExecutionPolicy -Scope Process Bypass -Force
  .\prepare-victim.ps1 [-SoIp 10.10.10.10] [-SoName td-so] [-SkipAtomic] [-AddDefenderExclusion]

What it does
  1. Adds the platform's name to the hosts file.
  2. Turns on the logging the TechDetechtives rules need:
     process creation with command line (4688), PowerShell Script Block and Module logging.
  3. Installs Sysmon (Sysinternals) with the SwiftOnSecurity configuration.
  4. Installs Invoke-AtomicRedTeam and the test definitions to C:\AtomicRedTeam.
  5. Optionally excludes C:\AtomicRedTeam from Microsoft Defender (-AddDefenderExclusion).
     Leave Defender on otherwise: "blocked" is a valid test result.

Elastic Agent is installed afterwards from the platform console (lab/README.md, phase 6).
Needs internet access for the downloads.
#>
[CmdletBinding()]
param(
  [string]$SoIp = "10.10.10.10",
  [string]$SoName = "td-so",
  [switch]$SkipAtomic,
  [switch]$AddDefenderExclusion
)
$ErrorActionPreference = "Stop"
function Log($m) { Write-Host "[lab:victim] $m" }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Run this in an elevated PowerShell." }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# 1. hosts file
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
if (-not (Select-String -Path $hosts -Pattern "\s$([regex]::Escape($SoName))(\s|$)" -Quiet)) {
  Add-Content -Path $hosts -Value "$SoIp`t$SoName" -Encoding ascii
  Log "added $SoIp $SoName to the hosts file"
} else { Log "$SoName already in the hosts file" }

# 2. logging
Log "enabling process creation auditing with command lines"
& auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
$audit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $audit -Force | Out-Null
Set-ItemProperty -Path $audit -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord

Log "enabling PowerShell Script Block and Module logging"
$ps = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
New-Item -Path "$ps\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "$ps\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord
New-Item -Path "$ps\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$ps\ModuleLogging" -Name EnableModuleLogging -Value 1 -Type DWord
Set-ItemProperty -Path "$ps\ModuleLogging\ModuleNames" -Name "*" -Value "*" -Type String

# 3. Sysmon
$work = Join-Path $env:TEMP "td-lab"
New-Item -ItemType Directory -Path $work -Force | Out-Null
if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
  Log "Sysmon already installed; updating its configuration"
  $sysmonExe = "$env:SystemRoot\Sysmon64.exe"
} else {
  Log "downloading Sysmon"
  Invoke-WebRequest -UseBasicParsing "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$work\Sysmon.zip"
  Expand-Archive -Path "$work\Sysmon.zip" -DestinationPath "$work\Sysmon" -Force
  $sysmonExe = "$work\Sysmon\Sysmon64.exe"
}
Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$work\sysmonconfig.xml"
if (Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue) {
  & $sysmonExe -c "$work\sysmonconfig.xml" | Out-Null
} else {
  & $sysmonExe -accepteula -i "$work\sysmonconfig.xml" | Out-Null
}
Log "Sysmon running: $((Get-Service Sysmon64).Status)"

# 4. Invoke-AtomicRedTeam
if (-not $SkipAtomic) {
  if ($AddDefenderExclusion) {
    New-Item -ItemType Directory -Path "C:\AtomicRedTeam" -Force | Out-Null
    Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
    Log "Defender exclusion added for C:\AtomicRedTeam (lab only)"
  }
  Log "installing Invoke-AtomicRedTeam and the atomics (a few minutes)"
  Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
  Install-Module -Name powershell-yaml -Scope AllUsers -Force
  IEX (IWR "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1" -UseBasicParsing)
  Install-AtomicRedTeam -getAtomics -Force -InstallPath "C:\AtomicRedTeam"
  $profileLine = 'Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force; $PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder"="C:\AtomicRedTeam\atomics"}'
  if (-not (Test-Path $PROFILE.AllUsersAllHosts)) { New-Item -ItemType File -Path $PROFILE.AllUsersAllHosts -Force | Out-Null }
  if (-not (Select-String -Path $PROFILE.AllUsersAllHosts -Pattern "Invoke-AtomicRedTeam.psd1" -Quiet)) {
    Add-Content -Path $PROFILE.AllUsersAllHosts -Value $profileLine
  }
  Log "Invoke-AtomicRedTeam ready in new PowerShell windows"
}

Log "done. Reboot once so the audit policy applies everywhere, then install Elastic Agent from the platform console."

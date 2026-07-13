 <#
.SYNOPSIS
    This PowerShell script ensures that the Windows Installer feature "Always install with elevated privileges" must be disabled.

.NOTES
    Author          : Malcolm Bell
    LinkedIn        : linkedin.com/in/malcolmtbell/
    GitHub          : github.com/malcolmtyronebell
    Date Created    : 2026-07-13
    Last Modified   : 2026-07-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000315
    Documentation   : https://stigaview.com/products/win11/v2r8/WN11-AU-000500/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(WN11-CC-000315).ps1 
#>

$Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'

if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

New-ItemProperty -Path $Path -Name 'AlwaysInstallElevated' -Value 0 -PropertyType DWord -Force | Out-Null

# Verify
$Value = (Get-ItemProperty -Path $Path -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
if ($null -eq $Value) {
    "FINDING (V-253411): AlwaysInstallElevated not configured."
} elseif ($Value -eq 0) {
    "NOT A FINDING (V-253411): AlwaysInstallElevated = 0."
} else {
    "FINDING (V-253411): AlwaysInstallElevated = $Value, must be 0."
} 

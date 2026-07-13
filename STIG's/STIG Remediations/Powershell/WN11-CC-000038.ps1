<#
.SYNOPSIS
    This PowerShell script ensures WDigest Authentication must be disabled.

.NOTES
    Author          : Malcolm Bell
    LinkedIn        : linkedin.com/in/malcolmtbell/
    GitHub          : github.com/malcolmtyronebell
    Date Created    : 2026-07-13
    Last Modified   : 2026-07-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000038
    Documentation   : https://stigaview.com/products/win11/v2r8/WN11-CC-0000380/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000038).ps1 
#>


$Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'

if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

New-ItemProperty -Path $Path -Name 'UseLogonCredential' -Value 0 -PropertyType DWord -Force | Out-Null

# Verify
$Value = (Get-ItemProperty -Path $Path -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
if ($null -eq $Value) {
    "FINDING (V-253358): UseLogonCredential not configured."
} elseif ($Value -eq 0) {
    "NOT A FINDING (V-253358): UseLogonCredential = 0 (WDigest disabled)."
} else {
    "FINDING (V-253358): UseLogonCredential = $Value, must be 0."
} 

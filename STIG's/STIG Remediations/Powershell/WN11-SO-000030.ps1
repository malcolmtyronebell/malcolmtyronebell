 <#
.SYNOPSIS
    This PowerShell script ensures Audit policy using subcategories must be enabled.

.NOTES
    Author          : Malcolm Bell
    LinkedIn        : linkedin.com/in/malcolmtbell/
    GitHub          : github.com/malcolmtyronebell
    Date Created    : 2026-07-13
    Last Modified   : 2026-07-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000030
    Documentation   : https://stigaview.com/products/win11/v2r8/WN11-SO-000030/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-SO-000030).ps1 
#>

$Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

New-ItemProperty -Path $Path -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -PropertyType DWord -Force | Out-Null

# Verify
$Value = (Get-ItemProperty -Path $Path -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy
if ($null -eq $Value) {
    "FINDING (V-253437): SCENoApplyLegacyAuditPolicy not configured."
} elseif ($Value -eq 1) {
    "NOT A FINDING (V-253437): SCENoApplyLegacyAuditPolicy = 1."
} else {
    "FINDING (V-253437): SCENoApplyLegacyAuditPolicy = $Value, must be 1."
} 

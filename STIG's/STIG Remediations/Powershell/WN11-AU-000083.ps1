<#
.SYNOPSIS
    This PowerShell script ensures Windows 11 must be configured to audit Object Access - Other Object Access Events successes.

.NOTES
    Author          : Malcolm Bell
    LinkedIn        : linkedin.com/in/malcolmtbell/
    GitHub          : github.com/malcolmtyronebell
    Date Created    : 2026-07-13
    Last Modified   : 2026-07-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000083
    Documentation   : https://stigaview.com/products/win11/v2r8/WN11-AU-0000830/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-AU-000083).ps1 
#>

$Subcategory = 'Other Object Access Events'

# Pre-remediation state
$Before = (auditpol /get /subcategory:"$Subcategory" | Select-String $Subcategory).ToString().Trim()
"Pre-remediation: $Before"

# Apply - Success auditing
auditpol /set /subcategory:"$Subcategory" /success:enable | Out-Null

# Verify
$After = (auditpol /get /subcategory:"$Subcategory" | Select-String $Subcategory).ToString()

if ($After -match 'Success and Failure' -or $After -match 'Success') {
    "NOT A FINDING (V-253321): $($After.Trim())"
} else {
    "FINDING (V-253321): $($After.Trim())"
} 

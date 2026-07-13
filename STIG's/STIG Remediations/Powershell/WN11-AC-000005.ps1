 <#
.SYNOPSIS
    This PowerShell script ensures Windows 11 account lockout duration must be configured to 15 minutes or greater.

.NOTES
    Author          : Malcolm Bell
    LinkedIn        : linkedin.com/in/malcolmtbell/
    GitHub          : github.com/malcolmtyronebell
    Date Created    : 2026-07-13
    Last Modified   : 2026-07-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AC-000005
    Documentation   : https://stigaview.com/products/win11/v2r8/WN11-AC-000005/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-AC-000005).ps1 
#>

$Inf = "$env:TEMP\lockout_duration.inf"
$Db  = "$env:TEMP\lockout_duration.sdb"
$Ver = "$env:TEMP\verify_duration.inf"

# Pre-remediation state
secedit /export /cfg $Inf /quiet
$Current = (Select-String -Path $Inf -Pattern 'LockoutDuration').ToString().Split('=')[1].Trim()
"Pre-remediation: LockoutDuration = $Current"

# Build minimal INF
@"
[Unicode]
Unicode=yes
[System Access]
LockoutDuration = 15
[Version]
signature="`$CHICAGO`$"
Revision=1
"@ | Out-File -FilePath $Inf -Encoding Unicode -Force

# Apply
secedit /configure /db $Db /cfg $Inf /areas SECURITYPOLICY /quiet

# Verify
secedit /export /cfg $Ver /quiet
$Value = [int](Select-String -Path $Ver -Pattern 'LockoutDuration').ToString().Split('=')[1].Trim()

if ($Value -eq 0) {
    "NOT A FINDING (V-253297): LockoutDuration = 0 (admin unlock required - more restrictive)."
} elseif ($Value -ge 15) {
    "NOT A FINDING (V-253297): LockoutDuration = $Value minutes."
} else {
    "FINDING (V-253297): LockoutDuration = $Value minutes, must be 15 or greater (or 0)."
}

Remove-Item $Inf, $Db, $Ver -ErrorAction SilentlyContinue 

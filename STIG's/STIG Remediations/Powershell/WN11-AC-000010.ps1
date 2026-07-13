 <#
.SYNOPSIS
    This PowerShell script ensures that The number of allowed bad logon attempts must be configured to three or less.

.NOTES
    Author          : Malcolm Bell
    LinkedIn        : linkedin.com/in/malcolmtbell/
    GitHub          : github.com/malcolmtyronebell
    Date Created    : 2026-07-13
    Last Modified   : 2026-07-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AC-000010
    Documentation   : https://stigaview.com/products/win11/v2r8/WN11-AC-000010/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(WWN11-AC-000010).ps1 
#>

$Inf = "$env:TEMP\lockout.inf"
$Db  = "$env:TEMP\lockout.sdb"

# Export current local security policy
secedit /export /cfg $Inf /quiet

# Read effective value
$Current = (Select-String -Path $Inf -Pattern 'LockoutBadCount').ToString().Split('=')[1].Trim()
"Pre-remediation: LockoutBadCount = $Current"

# Build minimal INF containing only the setting to change
@"
[Unicode]
Unicode=yes
[System Access]
LockoutBadCount = 3
[Version]
signature="`$CHICAGO`$"
Revision=1
"@ | Out-File -FilePath $Inf -Encoding Unicode -Force

# Apply
secedit /configure /db $Db /cfg $Inf /areas SECURITYPOLICY /quiet

# Verify
secedit /export /cfg "$env:TEMP\verify.inf" /quiet
$Value = [int](Select-String -Path "$env:TEMP\verify.inf" -Pattern 'LockoutBadCount').ToString().Split('=')[1].Trim()

if ($Value -eq 0) {
    "FINDING (V-253298): LockoutBadCount = 0 (never lock out)."
} elseif ($Value -ge 1 -and $Value -le 3) {
    "NOT A FINDING (V-253298): LockoutBadCount = $Value."
} else {
    "FINDING (V-253298): LockoutBadCount = $Value, must be 1-3."
}

Remove-Item $Inf, $Db, "$env:TEMP\verify.inf" -ErrorAction SilentlyContinue 

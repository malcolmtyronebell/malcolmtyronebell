<#
.SYNOPSIS
    This PowerShell script ensures the "Access this computer from the network" user right must only be assigned to the Administrators and Remote Desktop Users groups.

.NOTES
    Author          : Malcolm Bell
    LinkedIn        : linkedin.com/in/malcolmtbell/
    GitHub          : github.com/malcolmtyronebell
    Date Created    : 2026-07-13
    Last Modified   : 2026-07-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-UR-000010
    Documentation   : https://stigaview.com/products/win11/v2r8/WN11-UR-000010/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-UR-000010).ps1 
#>

$Inf = "$env:TEMP\ur000010.inf"
$Db  = "$env:TEMP\ur000010.sdb"
$Ver = "$env:TEMP\verify_ur000010.inf"

# Well-known SIDs
$Administrators      = 'S-1-5-32-544'
$RemoteDesktopUsers  = 'S-1-5-32-555'

# Pre-remediation state
secedit /export /cfg $Inf /quiet
$Current = (Select-String -Path $Inf -Pattern 'SeNetworkLogonRight').ToString().Split('=')[1].Trim()
"Pre-remediation: SeNetworkLogonRight = $Current"

# Build minimal INF - explicit list replaces existing assignment entirely
@"
[Unicode]
Unicode=yes
[Privilege Rights]
SeNetworkLogonRight = *$Administrators,*$RemoteDesktopUsers
[Version]
signature="`$CHICAGO`$"
Revision=1
"@ | Out-File -FilePath $Inf -Encoding Unicode -Force

# Apply
secedit /configure /db $Db /cfg $Inf /areas USER_RIGHTS /quiet

# Verify
secedit /export /cfg $Ver /quiet
$Value = (Select-String -Path $Ver -Pattern 'SeNetworkLogonRight').ToString().Split('=')[1].Trim()

$Assigned = $Value -split ',' | ForEach-Object { $_.Trim().TrimStart('*') }
$Allowed  = @($Administrators, $RemoteDesktopUsers)
$Extra    = $Assigned | Where-Object { $_ -notin $Allowed }

if ($Extra.Count -eq 0) {
    "NOT A FINDING (V-253480): SeNetworkLogonRight = $Value (Administrators, Remote Desktop Users only)."
} else {
    "FINDING (V-253480): Unauthorized principals hold SeNetworkLogonRight: $($Extra -join ', ')"
}

Remove-Item $Inf, $Db, $Ver -ErrorAction SilentlyContinue 


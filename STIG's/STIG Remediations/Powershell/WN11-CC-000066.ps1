<#
.SYNOPSIS
    This PowerShell script ensures command line data is included in process creation events.
.NOTES
    Author          : Malcolm Bell
    LinkedIn        : linkedin.com/in/malcolmtbell/
    GitHub          : github.com/malcolmtyronebell
    Date Created    : 2026-07-13
    Last Modified   : 2026-07-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000066
    Documentation   : https://stigaview.com/products/win11/v2r8/WN11-CC-000066/
.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 
.USAGE
    Run in an elevated PowerShell session.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN11-CC-000066).ps1
#>

#Requires -RunAsAdministrator

# ---------- PART 1: Registry (the STIG check) ----------
$Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'

if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

New-ItemProperty -Path $Path -Name 'ProcessCreationIncludeCmdLine_Enabled' `
                 -Value 1 -PropertyType DWord -Force | Out-Null

$Value = (Get-ItemProperty -Path $Path -Name ProcessCreationIncludeCmdLine_Enabled `
          -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled

if ($null -eq $Value) {
    "FINDING (V-253367): ProcessCreationIncludeCmdLine_Enabled not configured."
} elseif ($Value -eq 1) {
    "NOT A FINDING (V-253367): ProcessCreationIncludeCmdLine_Enabled = 1."
} else {
    "FINDING (V-253367): ProcessCreationIncludeCmdLine_Enabled = $Value, must be 1."
}

# ---------- PART 2: Audit Policy dependency (WN11-AU-000585) ----------
# The registry key above only populates the CommandLine field WHEN Event ID 4688
# fires. It does not cause 4688 to fire. Process Creation auditing must also be
# enabled or the system passes the STIG check while emitting zero telemetry.

# ---------- PART 2: Audit Policy dependency (WN11-AU-000585) ----------
$Subcategory = 'Process Creation'

$Before = (auditpol /get /subcategory:"$Subcategory" | Select-String $Subcategory).ToString().Trim()
"Pre-remediation: $Before"

auditpol /set /subcategory:"$Subcategory" /success:enable | Out-Null

$After = (auditpol /get /subcategory:"$Subcategory" | Select-String $Subcategory).ToString()
<#

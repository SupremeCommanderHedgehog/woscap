function Get-WoscapAnsibleAuditScript {
    <#
    .SYNOPSIS
        Returns the PowerShell script text embedded in each Ansible audit-policy task.
    .DESCRIPTION
        The script runs on the target under ansible.windows.win_powershell. It reads the
        subcategory's current inclusion setting with 'auditpol /get ... /r', enables only
        the required directions that are missing, and never passes a disable flag. It sets
        $Ansible.Changed only when something changed (or would change in check mode) and
        throws on a non-zero auditpol exit code. Subcategory and Directions arrive as
        win_powershell parameters, never interpolated into this text. The inclusion-setting
        parse mirrors ConvertFrom-AuditPolCsv so the playbook agrees with woscap's scan.
        Only auditpol's stdout is parsed; stderr appears solely in failure messages. The
        script declares SupportsShouldProcess because win_powershell otherwise skips it
        in check mode. This function only returns text; it executes nothing.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    @'
# SupportsShouldProcess: without it win_powershell skips the script under --check.
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)] [string] $Subcategory,
    [Parameter(Mandatory = $true)] [string[]] $Directions
)
# woscap enable-only audit fix: passes only enable flags, so a direction
# that is already audited stays on. Parsing matches woscap's own scan.
foreach ($d in $Directions) {
    if (@('success', 'failure') -notcontains $d) { throw "woscap: unknown audit direction '$d'." }
}
# Returns auditpol's stdout only; stderr is kept out of the CSV but reported on failure.
function Invoke-WoscapAuditPol([string[]] $ArgList) {
    $raw = @(& auditpol @ArgList 2>&1)
    $code = $LASTEXITCODE
    $stdout = @($raw | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })
    $stderr = @($raw | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })
    if ($code -ne 0) { throw "auditpol $($ArgList[0]) failed for '$Subcategory' (exit $code): $(($stderr + $stdout) -join ' ')" }
    $stdout
}
$out = @(Invoke-WoscapAuditPol @('/get', "/subcategory:$Subcategory", '/r'))
$row = @($out | Where-Object { $_.Trim() } | ConvertFrom-Csv | Where-Object { $_.'Subcategory' }) | Select-Object -First 1
if (-not $row) { throw "auditpol returned no row for '$Subcategory'." }
$setting = [string]$row.'Inclusion Setting'
$current = if ([string]::IsNullOrWhiteSpace($setting) -or $setting -eq 'No Auditing') { @() } else { @($setting -split '\s+and\s+') }
$missing = @($Directions | Where-Object { $current -notcontains $_ })
if ($missing.Count -eq 0) { $Ansible.Changed = $false; return }
$Ansible.Changed = $true
if ($Ansible.CheckMode) { return }
$setArgs = @('/set', "/subcategory:$Subcategory")
if ($missing -contains 'success') { $setArgs += '/success:enable' }
if ($missing -contains 'failure') { $setArgs += '/failure:enable' }
$null = Invoke-WoscapAuditPol $setArgs
'@
}

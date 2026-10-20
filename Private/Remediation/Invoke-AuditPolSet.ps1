function Invoke-AuditPolSet {
    # WRITE HELPER - part of the gated remediation path. Only ever ENABLES the required
    # directions; any direction not requested is left as-is, never disabled.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Subcategory,
        [Parameter(Mandatory)] [bool] $Success,
        [Parameter(Mandatory)] [bool] $Failure
    )
    if (-not ($Success -or $Failure)) {
        throw "woscap: no audit direction to enable for '$Subcategory'."
    }
    $arguments = @('/set', "/subcategory:$Subcategory")
    if ($Success) { $arguments += '/success:enable' }
    if ($Failure) { $arguments += '/failure:enable' }
    Invoke-AuditPolNative -Arguments $arguments | Out-Null
}

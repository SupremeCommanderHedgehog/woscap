function Invoke-AuditPolSet {
    # WRITE HELPER — part of the gated remediation path. Sets ABSOLUTE per-subcategory
    # state: directions not required by any Open rule are disabled to converge to the
    # STIG-required state. Delegates the exe call to the mockable native seam.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Subcategory,
        [Parameter(Mandatory)] [bool] $Success,
        [Parameter(Mandatory)] [bool] $Failure
    )
    $successFlag = if ($Success) { 'enable' } else { 'disable' }
    $failureFlag = if ($Failure) { 'enable' } else { 'disable' }
    $arguments = @('/set', "/subcategory:$Subcategory", "/success:$successFlag", "/failure:$failureFlag")
    Invoke-AuditPolNative -Arguments $arguments | Out-Null
}

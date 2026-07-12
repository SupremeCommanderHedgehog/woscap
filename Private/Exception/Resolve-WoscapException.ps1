function Resolve-WoscapException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $StigId,
        [Parameter(Mandatory)] [hashtable] $ExceptionProfile,
        [datetime] $ReferenceDate = (Get-Date)
    )
    if (-not $ExceptionProfile.ContainsKey($StigId)) { return $null }
    $ex = $ExceptionProfile[$StigId]
    if ($ex -isnot [hashtable]) {
        Write-Warning "woscap: exception for $StigId is malformed (not a table); ignored."
        return $null
    }
    if (Test-WoscapExceptionActive -Exception $ex -ReferenceDate $ReferenceDate) {
        return $ex
    }
    Write-Warning "woscap: exception for $StigId ignored (expired or invalid Expires: '$($ex['Expires'])')."
    return $null
}

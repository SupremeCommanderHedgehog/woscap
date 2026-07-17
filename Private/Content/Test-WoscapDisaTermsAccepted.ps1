function Test-WoscapDisaTermsAccepted {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $CacheRoot)

    # Read-only: true iff a persisted DISA-terms acknowledgement marker exists under the
    # cache root. Returns false for a cache root that does not yet exist (Test-Path copes).
    Test-Path -LiteralPath (Get-WoscapDisaMarkerPath -CacheRoot $CacheRoot)
}

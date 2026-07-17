function Get-WoscapDisaMarkerPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $CacheRoot)

    # Single source of truth for the persisted DISA-terms acknowledgement marker path.
    # Read-only: computes a path only; the Public orchestrator owns the actual write.
    Join-Path $CacheRoot '.woscap-disa-accepted'
}

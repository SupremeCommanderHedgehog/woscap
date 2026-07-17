function Get-WoscapContentSidecarPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $RevisionDir)

    # Single source of truth for the per-revision content sidecar path, mirroring
    # Get-WoscapDisaMarkerPath. Reused by the writer (Save-WoscapStigContent) and the reader
    # (Get-WoscapBenchmark) so the filename lives in one place. Read-only: computes a path only.
    Join-Path $RevisionDir '.woscap-content.json'
}

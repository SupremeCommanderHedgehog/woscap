function Get-WoscapContentCacheRoot {
    [CmdletBinding()]
    [OutputType([string])]
    param([string] $Destination)

    # Read-only by design: it only computes/normalizes the path. Directory
    # creation happens in the Public orchestrator, because Private/** is scanned
    # by tests/ReadOnly.Tests.ps1 and must contain no write cmdlets.
    $root = if ($Destination) { $Destination } else { Join-Path $env:LOCALAPPDATA 'woscap\content' }
    [System.IO.Path]::GetFullPath($root)
}

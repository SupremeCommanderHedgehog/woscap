function Resolve-WoscapStigUrl {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Benchmark,
        [string] $Url,
        [string] $ManifestPath
    )

    # Resolution order (Phase 2): explicit operator -Url wins; otherwise fall back to the
    # bundled benchmark->URL manifest. A Phase 3 DISA-page scraper will slot in as a third
    # resolver behind this same seam, so Save-WoscapStigContent never changes.
    if ($Url) { return $Url }

    $manifest = Get-WoscapStigManifest -Path $ManifestPath
    if ($manifest.ContainsKey($Benchmark) -and $manifest[$Benchmark]) {
        return [string]$manifest[$Benchmark]
    }

    throw "woscap: could not resolve STIG content for benchmark '$Benchmark'. Supply -Url with a direct DISA archive URL, or add '$Benchmark' to the bundled manifest (Content\stig-sources.psd1). (DISA-page resolution is planned for a later phase.)"
}

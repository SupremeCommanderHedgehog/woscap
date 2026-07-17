function Resolve-WoscapStigUrl {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Benchmark,
        [string] $Url,
        [string] $ManifestPath,
        [switch] $AllowScrape
    )

    # Resolution order: an explicit operator -Url always wins. Otherwise, when -AllowScrape is set
    # and the benchmark has a ScrapePattern, a best-effort scrape of the DISA downloads page is
    # tried FIRST (the operator explicitly asked for the latest), falling back to the bundled
    # manifest's pinned Url when the scrape yields nothing; without -AllowScrape the pinned manifest
    # Url is used directly. Save-WoscapStigContent forwards -AllowScrape so resolver strategy stays
    # in one place.
    if ($Url) { return $Url }

    $manifest = Get-WoscapStigManifest -Path $ManifestPath
    $entry = if ($manifest.ContainsKey($Benchmark)) { $manifest[$Benchmark] } else { $null }

    # Polymorphic entry: a string is a direct URL; a hashtable exposes optional Url + ScrapePattern.
    # One benchmark->source registry, backward-compatible with Phase 2 strings.
    $manifestUrl = $null
    $scrapePattern = $null
    if ($entry -is [hashtable]) {
        if ($entry.ContainsKey('Url') -and $entry['Url']) { $manifestUrl = [string] $entry['Url'] }
        if ($entry.ContainsKey('ScrapePattern') -and $entry['ScrapePattern']) { $scrapePattern = [string] $entry['ScrapePattern'] }
    } elseif ($entry) {
        $manifestUrl = [string] $entry
    }

    # -AllowScrape means "get the latest": prefer a freshly scraped URL over any pinned manifest Url.
    $scrapeAttempted = $false
    if ($AllowScrape -and $scrapePattern) {
        $scrapeAttempted = $true
        $html = Get-WoscapStigDownloadPage
        $scraped = Resolve-WoscapStigUrlFromPage -Html $html -Pattern $scrapePattern
        if ($scraped) { return $scraped }
    }

    if ($manifestUrl) { return $manifestUrl }

    $hint =
        if ($scrapeAttempted) {
            " A scrape of the DISA downloads page matched nothing for pattern '$scrapePattern' (the page layout may have changed)."
        } elseif ($scrapePattern) {
            " A scrape pattern is registered for '$Benchmark'; re-run with -AllowScrape to resolve the latest revision from the DISA downloads page."
        } else { '' }
    throw "woscap: could not resolve STIG content for benchmark '$Benchmark'. Supply -Url with a direct DISA archive URL, or add '$Benchmark' to the bundled manifest (Content\stig-sources.psd1).$hint"
}

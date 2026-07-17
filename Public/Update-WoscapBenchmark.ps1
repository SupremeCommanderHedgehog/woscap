function Update-WoscapBenchmark {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string] $Benchmark,
        [string] $Url,
        [switch] $AllowScrape,
        [switch] $AcceptDisaTerms,
        [string] $Destination
    )

    if ($Url -and -not $Benchmark) {
        throw 'woscap: -Url is only valid when a single -Benchmark is specified.'
    }
    if ($Benchmark) { Assert-WoscapSafePathSegment -Segment $Benchmark -Kind 'benchmark name' }

    $cacheRoot = Get-WoscapContentCacheRoot -Destination $Destination

    # Target set: an explicit -Benchmark, else every benchmark directory already in the cache
    # (skip transient staging dirs, same convention Get-WoscapBenchmark uses).
    $targets = if ($Benchmark) {
        @($Benchmark)
    } elseif (Test-Path -LiteralPath $cacheRoot) {
        @(Get-ChildItem -LiteralPath $cacheRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notlike '.staging-*' } | ForEach-Object { $_.Name })
    } else {
        @()
    }

    foreach ($b in $targets) {
        $beforeRevs = @(Get-WoscapBenchmark -Benchmark $b -Destination $Destination | ForEach-Object { $_.Revision })
        # Report the previously-newest revision. Sort numerically when the revision parses as an
        # integer (so '10' > '2'); fall back to the raw string for non-numeric revisions (e.g. 'unknown').
        $fromRev = if ($beforeRevs.Count -gt 0) {
            @($beforeRevs | Sort-Object {
                $n = 0
                if ([int]::TryParse($_, [ref] $n)) { '{0:D10}' -f $n } else { $_ }
            })[-1]
        } else { '' }

        try {
            $saveArgs = @{
                Benchmark       = $b
                Destination     = $Destination
                AllowScrape     = $AllowScrape
                AcceptDisaTerms = $AcceptDisaTerms
            }
            # Only include -Url when actually supplied (an empty string must not reach the resolver).
            if ($Url) { $saveArgs['Url'] = $Url }

            $path = Save-WoscapStigContent @saveArgs
            $toRev = Split-Path (Split-Path $path -Parent) -Leaf

            # Authoritative "did anything change": was this revision folder already present?
            $status = if ($beforeRevs -contains $toRev) { 'AlreadyCurrent' } else { 'Updated' }

            [pscustomobject]@{
                Benchmark    = $b
                Status       = $status
                FromRevision = $fromRev
                ToRevision   = $toRev
                Reason       = ''
            }
        } catch {
            [pscustomobject]@{
                Benchmark    = $b
                Status       = 'Failed'
                FromRevision = $fromRev
                ToRevision   = ''
                Reason       = [string] $_.Exception.Message
            }
        }
    }
}

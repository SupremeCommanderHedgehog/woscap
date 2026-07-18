function Update-WoscapBenchmark {
    <#
    .SYNOPSIS
        Re-resolves and fetches the latest revision of cached STIG benchmarks.
    .DESCRIPTION
        With -Benchmark, refreshes just that benchmark; without it, every benchmark
        already in the cache. Emits one row per benchmark
        (Updated / AlreadyCurrent / Failed). Because a bulk refresh fans out a live
        DISA scrape plus a download per cached benchmark, each per-benchmark refresh
        is gated by ShouldProcess (ConfirmImpact High) — it prompts per benchmark by
        default; suppress with -Confirm:$false. Use -WhatIf to preview which benchmarks
        would be re-resolved (Status='WhatIf') without performing any network I/O; a
        prompt declined at the confirmation gate is reported Status='Skipped'.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
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

        # Gate the network fan-out (scrape + per-benchmark download inside Save). ShouldProcess
        # returns $false for both -WhatIf and a declined confirmation prompt; neither performs any
        # network I/O. Distinguish them the way Invoke-WoscapRemediation does: -WhatIf is a dry-run
        # preview ('WhatIf'), an explicit decline is an operator choice ('Skipped').
        if (-not $PSCmdlet.ShouldProcess($b, 'Refresh from DISA')) {
            [pscustomobject]@{
                Benchmark    = $b
                Status       = if ($WhatIfPreference) { 'WhatIf' } else { 'Skipped' }
                FromRevision = $fromRev
                ToRevision   = ''
                Reason       = if ($WhatIfPreference) { 'Would refresh from DISA' } else { 'Declined at confirmation prompt' }
            }
            continue
        }

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

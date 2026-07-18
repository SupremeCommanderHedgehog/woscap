function Get-WoscapBenchmark {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string] $Benchmark,
        [string] $Destination
    )

    # Read-only inventory of the operator-local content cache. Walks
    # <cacheRoot>\<benchmark>\<revision>\, reads each .woscap-content.json sidecar, and emits
    # one row per cached revision. Never downloads and never mutates the cache.

    # Same path-segment guard the producer (Save-WoscapStigContent) applies to -Benchmark:
    # block a name like '..\..\Windows' that -LiteralPath would normalize out of the cache
    # root, causing this reader to enumerate/emit directories outside the operator-local cache.
    if ($Benchmark) { Assert-WoscapSafePathSegment -Segment $Benchmark -Kind 'benchmark name' }

    $cacheRoot = Get-WoscapContentCacheRoot -Destination $Destination
    if (-not (Test-Path -LiteralPath $cacheRoot)) { return }

    $benchDirs = if ($Benchmark) {
        $d = Join-Path $cacheRoot $Benchmark
        if (Test-Path -LiteralPath $d) { @(Get-Item -LiteralPath $d) } else { @() }
    } else {
        # Skip transient staging dirs; the marker is a file, so -Directory already excludes it.
        @(Get-ChildItem -LiteralPath $cacheRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notlike '.staging-*' })
    }

    foreach ($bd in $benchDirs) {
        $revDirs = @(Get-ChildItem -LiteralPath $bd.FullName -Directory -ErrorAction SilentlyContinue)
        foreach ($rd in $revDirs) {
            $xccdf = @(Get-ChildItem -LiteralPath $rd.FullName -Filter '*_Manual-xccdf.xml' -File -ErrorAction SilentlyContinue)
            # Skip a revision dir with no usable XCCDF (e.g. an interrupted -Force re-promote or a
            # manual cache edit): a row with an empty Path is not scannable and would only make a
            # caller that pipes .Path into Invoke-WoscapScan fail with an obscure path error.
            if ($xccdf.Count -eq 0) { continue }
            $sidecar = Get-WoscapContentSidecarPath -RevisionDir $rd.FullName
            $meta = if (Test-Path -LiteralPath $sidecar) {
                try { Get-Content -LiteralPath $sidecar -Raw | ConvertFrom-Json } catch { $null }
            } else { $null }

            # ContentHash is the XCCDF content hash. Fall back to hashing the XCCDF on disk when the
            # sidecar has no stored contentSha256 (a legacy cache written before content hashing), so
            # a same-revision content change is still detectable by Update-WoscapBenchmark on such a
            # cache. Once the revision is refreshed the sidecar carries the hash and no rehash occurs.
            # The hash is best-effort ('' on any read failure): this reader must never throw — it is a
            # read-only inventory, and its caller reads the before-snapshot outside a try/catch.
            $contentHash = Get-WoscapObjectProperty -InputObject $meta -Name 'contentSha256' -Default ''
            if (-not $contentHash) {
                $contentHash = try { (Get-FileHash -LiteralPath $xccdf[0].FullName -Algorithm SHA256).Hash } catch { '' }
            }

            [pscustomobject]@{
                Benchmark   = $bd.Name
                Revision    = $rd.Name
                Title       = Get-WoscapObjectProperty -InputObject $meta -Name 'title'     -Default ''
                SourceUrl   = Get-WoscapObjectProperty -InputObject $meta -Name 'sourceUrl' -Default ''
                ContentHash = $contentHash
                Path        = $xccdf[0].FullName
            }
        }
    }
}

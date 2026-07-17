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

            [pscustomobject]@{
                Benchmark = $bd.Name
                Revision  = $rd.Name
                Title     = Get-WoscapObjectProperty -InputObject $meta -Name 'title'     -Default ''
                SourceUrl = Get-WoscapObjectProperty -InputObject $meta -Name 'sourceUrl' -Default ''
                Path      = $xccdf[0].FullName
            }
        }
    }
}

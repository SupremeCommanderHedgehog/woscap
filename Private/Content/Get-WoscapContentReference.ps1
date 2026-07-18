function Get-WoscapContentReference {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $CacheRoot,
        [Parameter(Mandatory)] [string] $Benchmark,
        [Parameter(Mandatory)] [string] $SourceUrl
    )

    # Newest cached revision for <Benchmark> whose sidecar sourceUrl matches $SourceUrl,
    # returning its stored etag + archive hash + canonical xccdf path for the ETag
    # short-circuit. $null when there is no matching, well-formed reference. Read-only.
    $benchDir = Join-Path $CacheRoot $Benchmark
    if (-not (Test-Path -LiteralPath $benchDir)) { return $null }

    $candidates = foreach ($rd in Get-ChildItem -LiteralPath $benchDir -Directory -ErrorAction SilentlyContinue) {
        $sidecarPath = Get-WoscapContentSidecarPath -RevisionDir $rd.FullName
        if (-not (Test-Path -LiteralPath $sidecarPath)) { continue }
        $meta = try { Get-Content -LiteralPath $sidecarPath -Raw | ConvertFrom-Json } catch { $null }
        if (-not $meta) { continue }
        if ((Get-WoscapObjectProperty -InputObject $meta -Name 'sourceUrl' -Default '') -ne $SourceUrl) { continue }
        $xccdf = @(Get-ChildItem -LiteralPath $rd.FullName -Filter '*_Manual-xccdf.xml' -File -ErrorAction SilentlyContinue)
        if ($xccdf.Count -eq 0) { continue }
        [pscustomobject]@{
            Revision = $rd.Name
            Etag     = (Get-WoscapObjectProperty -InputObject $meta -Name 'etag' -Default '')
            Xccdf    = $xccdf[0].FullName
        }
    }
    $candidates = @($candidates)
    if ($candidates.Count -eq 0) { return $null }

    # Newest revision: numeric sort when the label parses as an integer (so '10' > '2'),
    # else raw string — the same ordering Update-WoscapBenchmark uses for FromRevision.
    @($candidates | Sort-Object {
        $n = 0
        if ([int]::TryParse($_.Revision, [ref] $n)) { '{0:D10}' -f $n } else { $_.Revision }
    })[-1]
}

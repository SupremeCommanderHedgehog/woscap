function Save-WoscapStigContent {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Benchmark,
        [string] $Url,
        [switch] $AcceptDisaTerms,
        [string] $Destination,
        [switch] $Force,
        [switch] $AllowScrape
    )

    # Path-segment safety: validate the operator-supplied benchmark name early — before any
    # network or filesystem work — so a name that could escape the cache root fails fast.
    Assert-WoscapSafePathSegment -Segment $Benchmark -Kind 'benchmark name'

    $cacheRoot = Get-WoscapContentCacheRoot -Destination $Destination

    $notice = @'
woscap does NOT bundle or redistribute DISA STIG content. This action downloads content
on demand from a URL you supply (or a bundled best-effort pointer) into an operator-local
cache. Your use of that content is governed by DISA's own terms (public.cyber.mil), not
this project.
'@

    # DISA terms gate. Satisfied by -AcceptDisaTerms (stateless, per-call) OR a persisted
    # acknowledgement marker under the cache root. When neither holds, ask once interactively;
    # on accept we remember it by writing the marker after the cache root exists (below).
    # Never proceeds silently. -AcceptDisaTerms itself writes no marker, so it stays a pure
    # per-call switch and does not disable the gate for later runs.
    $persistConsent = $false
    if (-not $AcceptDisaTerms -and -not (Test-WoscapDisaTermsAccepted -CacheRoot $cacheRoot)) {
        if (Get-WoscapDisaConsent -Notice $notice) {
            $persistConsent = $true
        } else {
            Write-Warning $notice
            throw "woscap: DISA terms not accepted. Re-run with -AcceptDisaTerms to download DISA STIG content."
        }
    }

    $sourceUrl = Resolve-WoscapStigUrl -Benchmark $Benchmark -Url $Url -AllowScrape:$AllowScrape
    # Create directories via [System.IO.Directory]::CreateDirectory (literal-path, recursive,
    # idempotent) — the .NET API takes the path verbatim, avoiding New-Item's glob handling of
    # bracket metacharacters in an operator-supplied -Destination.
    [System.IO.Directory]::CreateDirectory($cacheRoot) | Out-Null

    # Stage everything under the cache root; promote into <benchmark>\<revision>\
    # only after Import-Xccdf validates the content. Any failure discards staging
    # and never mutates a promoted revision.
    $staging = Join-Path $cacheRoot ('.staging-' + [guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($staging) | Out-Null
    try {
        $zipPath = Join-Path $staging 'archive.zip'
        # -ErrorAction Stop: on Windows PowerShell 5.1 an HTTP error can surface as a
        # non-terminating error and let execution fall through to a misleading extract
        # failure; Stop makes the download fail closed.
        Invoke-WebRequest -Uri $sourceUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop

        $arc = Read-WoscapStigArchive -ZipPath $zipPath
        # Strip any directory component the archive entry may carry, then validate the
        # bare name as a safe path segment before it is used to build staging/target
        # paths. Use $fileName (not $arc.FileName) everywhere downstream.
        $fileName = [System.IO.Path]::GetFileName($arc.FileName)
        Assert-WoscapSafePathSegment -Segment $fileName -Kind 'archive file name'
        $stagedXccdf = Join-Path $staging $fileName
        Write-WoscapText -Text $arc.Xml -Path $stagedXccdf

        # Validation gate — throws on a corrupt / non-Benchmark document.
        $rules = @(Import-Xccdf -Path $stagedXccdf)
        $revision = if ($rules.Count -gt 0 -and $rules[0].BenchmarkVersion) { $rules[0].BenchmarkVersion } else { 'unknown' }
        $title    = if ($rules.Count -gt 0) { $rules[0].Benchmark } else { '' }

        # Same guard as $Benchmark, applied to the archive-derived revision before it
        # becomes a path segment. Blocks a tampered <version> like '..\..\pwned' (or a
        # bare '.'/'..') from escaping the cache root via $target / Remove-Item.
        # 'unknown' passes.
        Assert-WoscapSafePathSegment -Segment $revision -Kind 'STIG revision'

        # Persist the interactive DISA-terms acknowledgement only now that the download AND
        # Import-Xccdf validation have succeeded — so an aborted/failed fetch never leaves a
        # marker that would silently satisfy the gate on later runs. This is fail-closed, like
        # the stage->promote below, and is the ONLY new write (Public/, not scanned read-only).
        # -AcceptDisaTerms writes no marker; it stays a pure per-call switch.
        if ($persistConsent) {
            $ack = [pscustomobject]@{
                acceptedDisaTerms = $true
                acceptedUtc       = (Get-Date).ToUniversalTime().ToString('o')
            } | ConvertTo-Json
            Write-WoscapText -Text $ack -Path (Get-WoscapDisaMarkerPath -CacheRoot $cacheRoot)
        }

        $target     = Join-Path (Join-Path $cacheRoot $Benchmark) $revision
        $finalXccdf = Join-Path $target $fileName

        # Reuse: the canonical file for this revision is already cached and not -Force
        # -> return it, leaving the promoted content untouched. Look for the specific
        # $fileName rather than the first wildcard match, so the returned path is
        # deterministic.
        if ((Test-Path -LiteralPath $target) -and -not $Force) {
            $candidate = Join-Path $target $fileName
            if (Test-Path -LiteralPath $candidate) { return $candidate }
        }

        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
        [System.IO.Directory]::CreateDirectory($target) | Out-Null
        Move-Item -LiteralPath $stagedXccdf -Destination $finalXccdf -Force

        $sidecar = [pscustomobject]@{
            benchmark         = $Benchmark
            revision          = $revision
            title             = $title
            sourceUrl         = $sourceUrl
            retrievedRevision = $revision
        } | ConvertTo-Json
        Write-WoscapText -Text $sidecar -Path (Get-WoscapContentSidecarPath -RevisionDir $target)

        return $finalXccdf
    } finally {
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    }
}

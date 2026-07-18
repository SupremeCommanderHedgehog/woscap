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

    # Cheap HEAD to learn the current ETag/Last-Modified. Runs always (including under
    # -Force) so the sidecar's etag is seeded even on a forced re-download; $null on any
    # failure (fail-open — never blocks the GET). Consumed by the sidecar write below and
    # the ETag short-circuit.
    $head = Get-WoscapStigHttpHead -Uri $sourceUrl
    # Normalize the HEAD values once ('' when the HEAD failed) — reused by the short-circuit,
    # the reuse/refresh path, and every sidecar write below.
    $headEtag = if ($head) { $head.ETag } else { '' }
    $headLm   = if ($head) { $head.LastModified } else { '' }

    # ETag short-circuit (optimization; never for -Force). If the newest cached revision
    # for this benchmark+URL carries a stored etag equal to the current HEAD etag, the
    # archive is unchanged — return the cached xccdf without downloading, unzipping, or
    # re-importing. A miss (no reference, empty etag, HEAD failure, or mismatch) falls
    # through to the normal GET below.
    if (-not $Force -and $headEtag) {
        $ref = Get-WoscapContentReference -CacheRoot $cacheRoot -Benchmark $Benchmark -SourceUrl $sourceUrl
        if ($ref -and $ref.Etag -and $ref.Etag -eq $headEtag) {
            # A short-circuit is a successful operation (validated cached content returned), so it
            # persists an interactive DISA-terms acceptance exactly as the download path does —
            # otherwise every unchanged run would re-prompt the operator forever. Best-effort:
            # persisting consent is a convenience, so a read-only cache must not turn this
            # "return already-cached content" path into a hard failure.
            if ($persistConsent) {
                try { Write-WoscapDisaTermsMarker -CacheRoot $cacheRoot }
                catch { Write-Warning "woscap: could not persist DISA-terms acceptance: $($_.Exception.Message)" }
            }
            return $ref.Xccdf
        }
    }

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
        # Hash the extracted XCCDF (the scanned content), NOT the archive: this is what defines a
        # revision's content, and it is stable across benign archive regeneration (e.g. a re-zipped
        # download whose internal timestamps differ but whose XCCDF is byte-identical). Drives both
        # the same-revision re-release detection below and Get-WoscapBenchmark's ContentHash.
        $contentSha256 = (Get-FileHash -LiteralPath $stagedXccdf -Algorithm SHA256).Hash

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
        # the stage->promote below. -AcceptDisaTerms writes no marker; it stays a pure per-call switch.
        if ($persistConsent) { Write-WoscapDisaTermsMarker -CacheRoot $cacheRoot }

        $target     = Join-Path (Join-Path $cacheRoot $Benchmark) $revision
        $finalXccdf = Join-Path $target $fileName

        # Reuse vs re-promote for an already-cached revision (not -Force). Compare the freshly
        # extracted XCCDF's content hash against what is promoted: use the sidecar's stored content
        # hash when present, else (legacy sidecar) hash the promoted XCCDF on disk. When unchanged,
        # reuse the promoted file and refresh the sidecar (best-effort) so a rotated ETag or a
        # legacy sidecar gains the metadata a future run needs to short-circuit — a read-only
        # revision dir must not turn a reuse into a hard failure. When changed (a same-revision
        # DISA re-release), fall through to the wipe+promote so the promoted file always matches
        # the recorded hash.
        if ((Test-Path -LiteralPath $target) -and -not $Force -and (Test-Path -LiteralPath $finalXccdf)) {
            $existingSidecar = Get-WoscapContentSidecarPath -RevisionDir $target
            $existingMeta = if (Test-Path -LiteralPath $existingSidecar) {
                try { Get-Content -LiteralPath $existingSidecar -Raw | ConvertFrom-Json } catch { $null }
            } else { $null }
            $storedHash   = Get-WoscapObjectProperty -InputObject $existingMeta -Name 'contentSha256' -Default ''
            $promotedHash = if ($storedHash) { $storedHash } else { (Get-FileHash -LiteralPath $finalXccdf -Algorithm SHA256).Hash }

            if ($promotedHash -eq $contentSha256) {
                $curEtag = Get-WoscapObjectProperty -InputObject $existingMeta -Name 'etag'         -Default ''
                $curLm   = Get-WoscapObjectProperty -InputObject $existingMeta -Name 'lastModified' -Default ''
                # Preserve the stored etag/lastModified when this run's HEAD didn't supply one, so a
                # transient HEAD failure never blanks good values and defeats the next short-circuit.
                $newEtag = if ($headEtag) { $headEtag } else { $curEtag }
                $newLm   = if ($headLm)   { $headLm }   else { $curLm }
                # Only rewrite when the sidecar would actually change (rotated etag/lastModified, or
                # a legacy sidecar with no stored hash), keeping reuse a no-op in the common case.
                if (-not $storedHash -or $newEtag -ne $curEtag -or $newLm -ne $curLm) {
                    $refreshed = New-WoscapContentSidecar -Benchmark $Benchmark -Revision $revision -Title $title -SourceUrl $sourceUrl -Etag $newEtag -LastModified $newLm -ContentSha256 $contentSha256
                    try { Write-WoscapText -Text $refreshed -Path $existingSidecar }
                    catch { Write-Warning "woscap: could not refresh content sidecar for '$Benchmark' revision '$revision': $($_.Exception.Message)" }
                }
                return $finalXccdf
            }
            # else: content differs -> re-release; fall through to the wipe+promote below.
        }

        if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
        [System.IO.Directory]::CreateDirectory($target) | Out-Null
        Move-Item -LiteralPath $stagedXccdf -Destination $finalXccdf -Force

        $sidecar = New-WoscapContentSidecar -Benchmark $Benchmark -Revision $revision -Title $title -SourceUrl $sourceUrl -Etag $headEtag -LastModified $headLm -ContentSha256 $contentSha256
        Write-WoscapText -Text $sidecar -Path (Get-WoscapContentSidecarPath -RevisionDir $target)

        return $finalXccdf
    } finally {
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    }
}

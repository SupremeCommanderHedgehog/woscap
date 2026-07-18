BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-save-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Tmp | Out-Null
    $script:Cache = Join-Path $script:Tmp 'cache'

    $fixtures = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures'
    $script:Fixtures = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures'

    # good.zip: real sample XCCDF (version '1') as a *_Manual-xccdf.xml entry
    $good = Join-Path $script:Tmp 'goodsrc'; New-Item -ItemType Directory -Path $good | Out-Null
    Copy-Item (Join-Path $fixtures 'sample-xccdf.xml') (Join-Path $good 'U_MS_Windows_11_STIG_V1R1_Manual-xccdf.xml')
    $script:GoodZip = Join-Path $script:Tmp 'good.zip'
    [System.IO.Compression.ZipFile]::CreateFromDirectory($good, $script:GoodZip)

    # bad.zip: a non-Benchmark document renamed to look like a manual XCCDF
    $bad = Join-Path $script:Tmp 'badsrc'; New-Item -ItemType Directory -Path $bad | Out-Null
    Set-Content -Path (Join-Path $bad 'X_Manual-xccdf.xml') -Value '<notabenchmark/>'
    $script:BadZip = Join-Path $script:Tmp 'bad.zip'
    [System.IO.Compression.ZipFile]::CreateFromDirectory($bad, $script:BadZip)

    # evil.zip: a VALID Benchmark doc whose <version> is a path-traversal string.
    # It must parse (so Import-Xccdf passes) yet be rejected by the revision guard.
    $evilXml = (Get-Content (Join-Path $fixtures 'sample-xccdf.xml') -Raw) -replace '<version>1</version>', '<version>..\..\woscap-pwned</version>'
    $evil = Join-Path $script:Tmp 'evilsrc'; New-Item -ItemType Directory -Path $evil | Out-Null
    Set-Content -Path (Join-Path $evil 'E_Manual-xccdf.xml') -Value $evilXml -Encoding UTF8
    $script:EvilZip = Join-Path $script:Tmp 'evil.zip'
    [System.IO.Compression.ZipFile]::CreateFromDirectory($evil, $script:EvilZip)
}
AfterAll {
    Remove-Module woscap -Force -ErrorAction SilentlyContinue
    Remove-Item $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Save-WoscapStigContent' {
    It 'is exported as a public command' {
        (Get-Command Save-WoscapStigContent -Module woscap -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }

    It 'downloads, extracts, validates, and returns the cached XCCDF path' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip; Cache = $script:Cache } {
            Mock Invoke-WebRequest {
                if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"v1"'; 'Last-Modified' = 'Wed, 01 Jan 2025 00:00:00 GMT' } } }
                else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            }

            $p = Save-WoscapStigContent -Benchmark 'Windows11' -Url 'https://disa/test.zip' -AcceptDisaTerms -Destination $Cache

            $p | Should -Exist
            $p | Should -Match 'Windows11[\\/]1[\\/].*_Manual-xccdf\.xml$'   # revision folder = XCCDF version '1'
            (Split-Path $p -Leaf) | Should -BeLike '*_Manual-xccdf.xml'
            (Join-Path (Split-Path $p -Parent) '.woscap-content.json') | Should -Exist
            Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter { $Method -ne 'Head' }

            $meta = Get-Content (Join-Path (Split-Path $p -Parent) '.woscap-content.json') -Raw | ConvertFrom-Json
            $meta.revision  | Should -Be '1'
            $meta.sourceUrl | Should -Be 'https://disa/test.zip'
        }
    }

    It 'evil.zip truly carries the malicious version as BenchmarkVersion (guard, not parse error, rejects it)' {
        InModuleScope woscap -Parameters @{ Zip = $script:EvilZip } {
            $arc = Read-WoscapStigArchive -ZipPath $Zip
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-evil-' + [guid]::NewGuid().ToString('N') + '.xml')
            try {
                Write-WoscapText -Text $arc.Xml -Path $tmp
                $rules = @(Import-Xccdf -Path $tmp)   # must NOT throw: the doc is a valid Benchmark
                $rules[0].BenchmarkVersion | Should -Be '..\..\woscap-pwned'
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'rejects an archive whose revision would traverse outside the cache root' {
        InModuleScope woscap -Parameters @{ Zip = $script:EvilZip; Cache = $script:Cache } {
            Mock Invoke-WebRequest {
                if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"v1"'; 'Last-Modified' = 'Wed, 01 Jan 2025 00:00:00 GMT' } } }
                else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            }
            { Save-WoscapStigContent -Benchmark 'EvilBench' -Url 'https://disa/e.zip' -AcceptDisaTerms -Destination $Cache } |
                Should -Throw -ExpectedMessage '*unsafe*revision*'
            # nothing escaped the cache root
            (Join-Path (Split-Path $Cache -Parent) 'woscap-pwned') | Should -Not -Exist
        }
    }

    It 'rejects an unsafe -Benchmark name before downloading' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            Mock Invoke-WebRequest { if ($Method -eq 'Head') { $null } }
            { Save-WoscapStigContent -Benchmark '..\..\evil' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $Cache } |
                Should -Throw -ExpectedMessage '*unsafe benchmark*'
            Should -Invoke Invoke-WebRequest -Times 0 -Exactly -ParameterFilter { $Method -ne 'Head' }
        }
    }

    It 'refuses without -AcceptDisaTerms (declined) and never downloads' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            Mock Invoke-WebRequest { if ($Method -eq 'Head') { $null } }
            Mock Get-WoscapDisaConsent { $false }
            { Save-WoscapStigContent -Benchmark 'Windows11' -Url 'https://disa/x.zip' -Destination $Cache -WarningAction SilentlyContinue } |
                Should -Throw -ExpectedMessage '*DISA*'
            Should -Invoke Invoke-WebRequest -Times 0 -Exactly -ParameterFilter { $Method -ne 'Head' }
            (Get-WoscapDisaMarkerPath -CacheRoot $Cache) | Should -Not -Exist
        }
    }

    It 'proceeds without -AcceptDisaTerms when a persisted marker is present' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip } {
            Mock Invoke-WebRequest {
                if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"v1"'; 'Last-Modified' = 'Wed, 01 Jan 2025 00:00:00 GMT' } } }
                else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            }
            Mock Get-WoscapDisaConsent { throw 'consent should not be requested when a marker exists' }
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-marker-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $cache | Out-Null
            Set-Content -LiteralPath (Get-WoscapDisaMarkerPath -CacheRoot $cache) -Value 'x'
            try {
                $p = Save-WoscapStigContent -Benchmark 'MarkerBench' -Url 'https://disa/x.zip' -Destination $cache
                $p | Should -Exist
                Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter { $Method -ne 'Head' }
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'interactive accept downloads AND persists a marker for next time' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip } {
            Mock Invoke-WebRequest {
                if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"v1"'; 'Last-Modified' = 'Wed, 01 Jan 2025 00:00:00 GMT' } } }
                else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            }
            Mock Get-WoscapDisaConsent { $true }
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-consent-' + [guid]::NewGuid().ToString('N'))
            try {
                $p = Save-WoscapStigContent -Benchmark 'ConsentBench' -Url 'https://disa/x.zip' -Destination $cache
                $p | Should -Exist
                (Get-WoscapDisaMarkerPath -CacheRoot $cache) | Should -Exist
                Should -Invoke Get-WoscapDisaConsent -Times 1 -Exactly
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'does not persist the DISA marker when the download fails after interactive accept' {
        InModuleScope woscap {
            Mock Invoke-WebRequest { if ($Method -eq 'Head') { $null } else { throw 'network down' } }
            Mock Get-WoscapDisaConsent { $true }
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-failmark-' + [guid]::NewGuid().ToString('N'))
            try {
                { Save-WoscapStigContent -Benchmark 'FailBench' -Url 'https://disa/x.zip' -Destination $cache } | Should -Throw
                (Get-WoscapDisaMarkerPath -CacheRoot $cache) | Should -Not -Exist
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    It '-AcceptDisaTerms writes no marker (stays a pure per-call switch)' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip } {
            Mock Invoke-WebRequest {
                if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"v1"'; 'Last-Modified' = 'Wed, 01 Jan 2025 00:00:00 GMT' } } }
                else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            }
            Mock Get-WoscapDisaConsent { throw 'consent must not be requested when -AcceptDisaTerms is passed' }
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-noswitch-' + [guid]::NewGuid().ToString('N'))
            try {
                $null = Save-WoscapStigContent -Benchmark 'SwitchBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache
                (Get-WoscapDisaMarkerPath -CacheRoot $cache) | Should -Not -Exist
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'throws a clear message and never downloads when no URL is resolvable' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            Mock Invoke-WebRequest { if ($Method -eq 'Head') { $null } }
            { Save-WoscapStigContent -Benchmark 'UnlistedBench' -AcceptDisaTerms -Destination $Cache } |
                Should -Throw -ExpectedMessage '*-Url*'
            Should -Invoke Invoke-WebRequest -Times 0 -Exactly -ParameterFilter { $Method -ne 'Head' }
        }
    }

    It 'fails fast on a non-Benchmark archive and leaves the cache clean' {
        InModuleScope woscap -Parameters @{ Zip = $script:BadZip; Cache = $script:Cache } {
            Mock Invoke-WebRequest {
                if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"v1"'; 'Last-Modified' = 'Wed, 01 Jan 2025 00:00:00 GMT' } } }
                else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            }
            { Save-WoscapStigContent -Benchmark 'BadBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $Cache } |
                Should -Throw -ExpectedMessage '*Benchmark*'
            (Join-Path $Cache 'BadBench') | Should -Not -Exist
            @(Get-ChildItem -LiteralPath $Cache -Directory -Filter '.staging-*' -ErrorAction SilentlyContinue).Count | Should -Be 0
        }
    }

    It 'reuses a cached revision without re-promoting when -Force is absent' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip; Cache = $script:Cache } {
            Mock Invoke-WebRequest {
                if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"v1"'; 'Last-Modified' = 'Wed, 01 Jan 2025 00:00:00 GMT' } } }
                else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            }
            $p1 = Save-WoscapStigContent -Benchmark 'ReuseBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $Cache
            $revDir = Split-Path $p1 -Parent
            Set-Content -Path (Join-Path $revDir 'sentinel.txt') -Value 'keep'
            $p2 = Save-WoscapStigContent -Benchmark 'ReuseBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $Cache
            $p2 | Should -Be $p1
            (Join-Path $revDir 'sentinel.txt') | Should -Exist
        }
    }
    It 're-promotes (wipes the revision dir) when -Force is set' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip; Cache = $script:Cache } {
            Mock Invoke-WebRequest {
                if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"v1"'; 'Last-Modified' = 'Wed, 01 Jan 2025 00:00:00 GMT' } } }
                else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            }
            $p1 = Save-WoscapStigContent -Benchmark 'ForceBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $Cache
            $revDir = Split-Path $p1 -Parent
            Set-Content -Path (Join-Path $revDir 'sentinel.txt') -Value 'wipe'
            $p2 = Save-WoscapStigContent -Benchmark 'ForceBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $Cache -Force
            $p2 | Should -Be $p1
            (Join-Path $revDir 'sentinel.txt') | Should -Not -Exist
            Should -Invoke Invoke-WebRequest -Times 2 -Exactly -ParameterFilter { $Method -ne 'Head' }
        }
    }
    It 'passes -AllowScrape through to resolution' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip; Cache = $script:Cache } {
            Mock Invoke-WebRequest {
                if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"v1"'; 'Last-Modified' = 'Wed, 01 Jan 2025 00:00:00 GMT' } } }
                else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            }
            # Stub the resolver so the assertion is purely "did Save forward -AllowScrape".
            Mock Resolve-WoscapStigUrl { 'https://disa/U_ScrapeOnly_V1R2_STIG.zip' } -ParameterFilter { $AllowScrape }
            $p = Save-WoscapStigContent -Benchmark 'ScrapeOnly' -AllowScrape -AcceptDisaTerms -Destination $Cache
            $p | Should -Exist
            Should -Invoke Resolve-WoscapStigUrl -Times 1 -Exactly -ParameterFilter { $AllowScrape }
        }
    }
    It 'never scrapes before the terms gate is satisfied' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            Mock Invoke-WebRequest { if ($Method -eq 'Head') { $null } }
            Mock Get-WoscapStigDownloadPage { throw 'scrape must not run before consent' }
            Mock Get-WoscapDisaConsent { $false }
            { Save-WoscapStigContent -Benchmark 'Windows11' -AllowScrape -Destination $Cache -WarningAction SilentlyContinue } |
                Should -Throw -ExpectedMessage '*DISA*'
            Should -Invoke Get-WoscapStigDownloadPage -Times 0 -Exactly
        }
    }

    It 'records etag, lastModified, and contentSha256 in the sidecar' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip } {
            Mock Invoke-WebRequest {
                if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"tag-1"'; 'Last-Modified' = 'Wed, 01 Jan 2025 00:00:00 GMT' } } }
                else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            }
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-meta-' + [guid]::NewGuid().ToString('N'))
            try {
                $p = Save-WoscapStigContent -Benchmark 'MetaBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache
                $meta = Get-Content (Join-Path (Split-Path $p -Parent) '.woscap-content.json') -Raw | ConvertFrom-Json
                $meta.etag          | Should -Be '"tag-1"'
                $meta.lastModified  | Should -Be 'Wed, 01 Jan 2025 00:00:00 GMT'
                $meta.contentSha256 | Should -Not -BeNullOrEmpty
                # contentSha256 is the hash of the promoted XCCDF content, not the archive.
                $meta.contentSha256 | Should -Be (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'short-circuits (no GET) when the HEAD ETag matches the cached revision' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-sc-' + [guid]::NewGuid().ToString('N'))
            try {
                # Seed revision '1' with a sidecar carrying etag "sc-tag" (no download involved).
                $rd = Join-Path (Join-Path $cache 'ScBench') '1'
                New-Item -ItemType Directory -Path $rd -Force | Out-Null
                $xccdf = Join-Path $rd 'U_x_Manual-xccdf.xml'
                Copy-Item -LiteralPath (Join-Path $Fixtures 'sample-xccdf.xml') -Destination $xccdf
                Set-Content -LiteralPath (Get-WoscapContentSidecarPath -RevisionDir $rd) -Value (@{
                    benchmark = 'ScBench'; revision = '1'; sourceUrl = 'https://disa/x.zip'
                    etag = '"sc-tag"'; contentSha256 = 'seeded'
                } | ConvertTo-Json)
                Set-Content -Path (Join-Path $rd 'sentinel.txt') -Value 'keep'

                # HEAD returns the same etag -> must short-circuit; any GET throws.
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"sc-tag"' } } }
                    else { throw 'must not GET on an unchanged ETag' }
                }
                $p = Save-WoscapStigContent -Benchmark 'ScBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache
                $p | Should -Be $xccdf
                (Join-Path $rd 'sentinel.txt') | Should -Exist
                Should -Invoke Invoke-WebRequest -Times 0 -Exactly -ParameterFilter { $Method -ne 'Head' }
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'does NOT short-circuit when the HEAD ETag differs (re-downloads)' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures; Zip = $script:GoodZip } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-sc2-' + [guid]::NewGuid().ToString('N'))
            try {
                $rd = Join-Path (Join-Path $cache 'ScBench2') '1'
                New-Item -ItemType Directory -Path $rd -Force | Out-Null
                Copy-Item -LiteralPath (Join-Path $Fixtures 'sample-xccdf.xml') -Destination (Join-Path $rd 'U_x_Manual-xccdf.xml')
                Set-Content -LiteralPath (Get-WoscapContentSidecarPath -RevisionDir $rd) -Value (@{
                    benchmark = 'ScBench2'; revision = '1'; sourceUrl = 'https://disa/x.zip'
                    etag = '"tag-A"'; contentSha256 = 'old-hash'
                } | ConvertTo-Json)

                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"tag-B"' } } }
                    else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
                }
                $null = Save-WoscapStigContent -Benchmark 'ScBench2' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache
                Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter { $Method -ne 'Head' }  # the differing ETag forced a GET
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It '-Force ignores a matching ETag and re-downloads' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures; Zip = $script:GoodZip } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-sc3-' + [guid]::NewGuid().ToString('N'))
            try {
                $rd = Join-Path (Join-Path $cache 'ScBench3') '1'
                New-Item -ItemType Directory -Path $rd -Force | Out-Null
                Copy-Item -LiteralPath (Join-Path $Fixtures 'sample-xccdf.xml') -Destination (Join-Path $rd 'U_x_Manual-xccdf.xml')
                Set-Content -LiteralPath (Get-WoscapContentSidecarPath -RevisionDir $rd) -Value (@{
                    benchmark = 'ScBench3'; revision = '1'; sourceUrl = 'https://disa/x.zip'
                    etag = '"same"'; contentSha256 = 'seeded'
                } | ConvertTo-Json)

                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"same"' } } }
                    else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
                }
                # -Force must skip the short-circuit even though the ETag matches.
                $null = Save-WoscapStigContent -Benchmark 'ScBench3' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache -Force
                Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter { $Method -ne 'Head' }
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 're-promotes fresh bytes on a same-revision re-release (different hash), no -Force' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures; Tmp = $script:Tmp } {
            # Build two revision-'1' zips with different content (extra comment => different bytes/hash).
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $mk = {
                param($marker, $zipPath)
                $src = Join-Path $Tmp ('rel-' + [guid]::NewGuid().ToString('N'))
                New-Item -ItemType Directory -Path $src | Out-Null
                $xml = (Get-Content (Join-Path $Fixtures 'sample-xccdf.xml') -Raw) + "<!-- $marker -->"
                Set-Content -Path (Join-Path $src 'U_MS_Windows_11_STIG_V1R1_Manual-xccdf.xml') -Value $xml -Encoding UTF8
                [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $zipPath)
            }
            $zipA = Join-Path $Tmp ('relA-' + [guid]::NewGuid().ToString('N') + '.zip'); & $mk 'A' $zipA
            $zipB = Join-Path $Tmp ('relB-' + [guid]::NewGuid().ToString('N') + '.zip'); & $mk 'B' $zipB
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-rel-' + [guid]::NewGuid().ToString('N'))
            try {
                # First save (archive A), ETag "old".
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"old"' } } }
                    else { Copy-Item -LiteralPath $zipA -Destination $OutFile -Force }
                }
                $p1 = Save-WoscapStigContent -Benchmark 'RelBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache
                $hashA = (Get-Content (Join-Path (Split-Path $p1 -Parent) '.woscap-content.json') -Raw | ConvertFrom-Json).contentSha256

                # Re-release (archive B) under a NEW ETag so the short-circuit does not fire.
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"new"' } } }
                    else { Copy-Item -LiteralPath $zipB -Destination $OutFile -Force }
                }
                $p2 = Save-WoscapStigContent -Benchmark 'RelBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache
                $p2 | Should -Be $p1                                   # same revision '1' path
                $meta2 = Get-Content (Join-Path (Split-Path $p2 -Parent) '.woscap-content.json') -Raw | ConvertFrom-Json
                $meta2.contentSha256 | Should -Not -Be $hashA         # cache refreshed to B's bytes
                (Get-Content $p2 -Raw) | Should -Match '<!-- B -->'
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'backfills a legacy sidecar (no contentSha256) and reuses the cached content' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-legacy-' + [guid]::NewGuid().ToString('N'))
            try {
                # Seed a legacy revision '1' whose sidecar predates etag/hash.
                $rd = Join-Path (Join-Path $cache 'LegacyBench') '1'
                New-Item -ItemType Directory -Path $rd -Force | Out-Null
                $xml = Get-Content (Join-Path $Fixtures 'sample-xccdf.xml') -Raw
                Set-Content -Path (Join-Path $rd 'U_MS_Windows_11_STIG_V1R1_Manual-xccdf.xml') -Value $xml -Encoding UTF8
                Set-Content -LiteralPath (Get-WoscapContentSidecarPath -RevisionDir $rd) -Value (@{
                    benchmark = 'LegacyBench'; revision = '1'; sourceUrl = 'https://disa/x.zip'
                } | ConvertTo-Json)
                Set-Content -LiteralPath (Get-WoscapDisaMarkerPath -CacheRoot $cache) -Value 'x'

                # Build a zip with the SAME bytes as the seeded xccdf so content matches on re-save.
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                $src = Join-Path $cache ('src-' + [guid]::NewGuid().ToString('N'))
                New-Item -ItemType Directory -Path $src | Out-Null
                Set-Content -Path (Join-Path $src 'U_MS_Windows_11_STIG_V1R1_Manual-xccdf.xml') -Value $xml -Encoding UTF8
                $zip = Join-Path $cache 'legacy.zip'
                [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $zip)

                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"backfill"' } } }
                    else { Copy-Item -LiteralPath $zip -Destination $OutFile -Force }
                }
                $p = Save-WoscapStigContent -Benchmark 'LegacyBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache
                $meta = Get-Content (Join-Path (Split-Path $p -Parent) '.woscap-content.json') -Raw | ConvertFrom-Json
                $meta.etag          | Should -Be '"backfill"'          # etag now seeded
                $meta.contentSha256 | Should -Not -BeNullOrEmpty       # hash now recorded
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'legacy sidecar + genuine re-release re-promotes the fresh content (no stale bytes, hash matches file)' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures; Tmp = $script:Tmp } {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            # A revision-'1' archive whose bytes carry a marker, so "same revision, different content".
            $mkZip = {
                param($marker, $zipPath)
                $src = Join-Path $Tmp ('lrel-' + [guid]::NewGuid().ToString('N'))
                New-Item -ItemType Directory -Path $src | Out-Null
                $xml = (Get-Content (Join-Path $Fixtures 'sample-xccdf.xml') -Raw) + "<!-- $marker -->"
                Set-Content -Path (Join-Path $src 'U_MS_Windows_11_STIG_V1R1_Manual-xccdf.xml') -Value $xml -Encoding UTF8
                [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $zipPath)
            }
            $zipB = Join-Path $Tmp ('lrelB-' + [guid]::NewGuid().ToString('N') + '.zip'); & $mkZip 'B' $zipB
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-lrel-' + [guid]::NewGuid().ToString('N'))
            try {
                # Seed a legacy revision '1' holding content 'A' with a sidecar that predates the hash.
                $rd = Join-Path (Join-Path $cache 'LRel') '1'
                New-Item -ItemType Directory -Path $rd -Force | Out-Null
                $finalName = 'U_MS_Windows_11_STIG_V1R1_Manual-xccdf.xml'
                Set-Content -Path (Join-Path $rd $finalName) -Value ((Get-Content (Join-Path $Fixtures 'sample-xccdf.xml') -Raw) + '<!-- A -->') -Encoding UTF8
                Set-Content -LiteralPath (Get-WoscapContentSidecarPath -RevisionDir $rd) -Value (@{
                    benchmark = 'LRel'; revision = '1'; sourceUrl = 'https://disa/x.zip'   # no etag / contentSha256 (legacy)
                } | ConvertTo-Json)
                Set-Content -LiteralPath (Get-WoscapDisaMarkerPath -CacheRoot $cache) -Value 'x'

                # New ETag (no stored etag anyway) -> no short-circuit; GET returns the different 'B' archive.
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"lrel"' } } }
                    else { Copy-Item -LiteralPath $zipB -Destination $OutFile -Force }
                }
                $p = Save-WoscapStigContent -Benchmark 'LRel' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache
                # The promoted content must be the FRESH 'B', not the stale seeded 'A'.
                (Get-Content $p -Raw) | Should -Match '<!-- B -->'
                (Get-Content $p -Raw) | Should -Not -Match '<!-- A -->'
                # And ContentHash must not lie: the recorded content hash matches the promoted file.
                $meta = Get-Content (Join-Path (Split-Path $p -Parent) '.woscap-content.json') -Raw | ConvertFrom-Json
                $meta.contentSha256 | Should -Be (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'ETag short-circuit persists an interactive DISA-terms acceptance (no re-prompt next run)' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-scc-' + [guid]::NewGuid().ToString('N'))
            try {
                # Seed revision '1' with a matching etag, and NO DISA marker (so consent must be sought).
                $rd = Join-Path (Join-Path $cache 'SccBench') '1'
                New-Item -ItemType Directory -Path $rd -Force | Out-Null
                Copy-Item -LiteralPath (Join-Path $Fixtures 'sample-xccdf.xml') -Destination (Join-Path $rd 'U_x_Manual-xccdf.xml')
                Set-Content -LiteralPath (Get-WoscapContentSidecarPath -RevisionDir $rd) -Value (@{
                    benchmark = 'SccBench'; revision = '1'; sourceUrl = 'https://disa/x.zip'; etag = '"sc"'
                } | ConvertTo-Json)

                Mock Get-WoscapDisaConsent { $true }   # operator accepts at the prompt
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"sc"' } } }
                    else { throw 'must not GET on a short-circuit' }
                }
                # No -AcceptDisaTerms: the terms gate goes interactive, accept -> persistConsent.
                $null = Save-WoscapStigContent -Benchmark 'SccBench' -Url 'https://disa/x.zip' -Destination $cache
                (Get-WoscapDisaMarkerPath -CacheRoot $cache) | Should -Exist   # acceptance was remembered
                Should -Invoke Invoke-WebRequest -Times 0 -Exactly -ParameterFilter { $Method -ne 'Head' }
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'hash-equal reuse refreshes a rotated ETag so a later run can short-circuit' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-rot-' + [guid]::NewGuid().ToString('N'))
            try {
                # First save (HEAD etag "old") establishes the sidecar with the correct content hash.
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"old"' } } }
                    else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
                }
                $p = Save-WoscapStigContent -Benchmark 'RotBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache
                ((Get-Content (Join-Path (Split-Path $p -Parent) '.woscap-content.json') -Raw | ConvertFrom-Json).etag) | Should -Be '"old"'

                # Second save: HEAD advertises a NEW etag (differs from stored -> no short-circuit);
                # GET returns identical content (hash matches -> unchanged -> reuse + rotate the etag).
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"new"' } } }
                    else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
                }
                $p2 = Save-WoscapStigContent -Benchmark 'RotBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache
                $p2 | Should -Be $p   # reused, not re-promoted to a different path
                ((Get-Content (Join-Path (Split-Path $p2 -Parent) '.woscap-content.json') -Raw | ConvertFrom-Json).etag) | Should -Be '"new"'
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'a failed HEAD on reuse preserves the stored ETag (does not blank it)' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-hf-' + [guid]::NewGuid().ToString('N'))
            try {
                # First save (HEAD etag "keep") seeds a good stored etag.
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"keep"' } } }
                    else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
                }
                $p = Save-WoscapStigContent -Benchmark 'HfBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache

                # Second save: the HEAD fails (helper returns $null -> headEtag ''); content is
                # unchanged so we reuse. The stored etag must NOT be overwritten with ''.
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { throw 'HEAD down' }
                    else { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
                }
                $null = Save-WoscapStigContent -Benchmark 'HfBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache
                ((Get-Content (Join-Path (Split-Path $p -Parent) '.woscap-content.json') -Raw | ConvertFrom-Json).etag) | Should -Be '"keep"'
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'a short-circuit still returns cached content when persisting consent fails (read-only cache)' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-roc-' + [guid]::NewGuid().ToString('N'))
            try {
                $rd = Join-Path (Join-Path $cache 'RocBench') '1'
                New-Item -ItemType Directory -Path $rd -Force | Out-Null
                $xccdf = Join-Path $rd 'U_x_Manual-xccdf.xml'
                Copy-Item -LiteralPath (Join-Path $Fixtures 'sample-xccdf.xml') -Destination $xccdf
                Set-Content -LiteralPath (Get-WoscapContentSidecarPath -RevisionDir $rd) -Value (@{
                    benchmark = 'RocBench'; revision = '1'; sourceUrl = 'https://disa/x.zip'; etag = '"sc"'
                } | ConvertTo-Json)

                Mock Get-WoscapDisaConsent { $true }                              # interactive accept -> persistConsent
                Mock Write-WoscapDisaTermsMarker { throw 'cache is read-only' }    # marker write fails
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"sc"' } } }
                    else { throw 'must not GET on a short-circuit' }
                }
                # Best-effort: the failed marker write must not stop the short-circuit returning content.
                $p = Save-WoscapStigContent -Benchmark 'RocBench' -Url 'https://disa/x.zip' -Destination $cache -WarningAction SilentlyContinue
                $p | Should -Be $xccdf
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

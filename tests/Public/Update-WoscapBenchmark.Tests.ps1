BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-upd-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Tmp | Out-Null
    $script:Fixtures = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures'

    # Build a zip whose XCCDF version we can vary, so a "new revision" is a different folder.
    # Uses $script:-scoped state so it resolves inside the function's own scope (a BeforeAll-local
    # would be invisible here).
    function script:New-RevZip([string] $Version, [string] $ZipPath) {
        $src = Join-Path $script:Tmp ('src-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $src | Out-Null
        $xml = (Get-Content (Join-Path $script:Fixtures 'sample-xccdf.xml') -Raw) -replace '<version>1</version>', "<version>$Version</version>"
        Set-Content -Path (Join-Path $src "U_MS_Windows_11_${Version}_Manual-xccdf.xml") -Value $xml -Encoding UTF8
        [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $ZipPath)
    }
    $script:ZipV1 = Join-Path $script:Tmp 'v1.zip'; New-RevZip -Version '1' -ZipPath $script:ZipV1
    $script:ZipV2 = Join-Path $script:Tmp 'v2.zip'; New-RevZip -Version '2' -ZipPath $script:ZipV2

    # Seed one cached <Benchmark>\<Revision> directly on disk (valid sidecar, no download) so
    # Get-WoscapBenchmark lists it. Defined in module scope because the sidecar/marker path
    # helpers are module-internal; persists to the It blocks' own InModuleScope re-entries.
    InModuleScope woscap {
        function script:New-SeededBench {
            param([string] $Cache, [string] $Benchmark, [string] $Revision, [string] $Fixtures)
            $rd = Join-Path (Join-Path $Cache $Benchmark) $Revision
            New-Item -ItemType Directory -Path $rd -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $Fixtures 'sample-xccdf.xml') -Destination (Join-Path $rd 'U_x_Manual-xccdf.xml')
            Set-Content -LiteralPath (Get-WoscapContentSidecarPath -RevisionDir $rd) -Value (@{ benchmark = $Benchmark; revision = $Revision } | ConvertTo-Json)
            Set-Content -LiteralPath (Get-WoscapDisaMarkerPath -CacheRoot $Cache) -Value 'x'
            $rd
        }
    }
}
AfterAll {
    Remove-Module woscap -Force -ErrorAction SilentlyContinue
    Remove-Item $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Update-WoscapBenchmark' {
    It 'is exported as a public command' {
        Get-Command Update-WoscapBenchmark -Module woscap | Should -Not -BeNullOrEmpty
    }

    It 'declares SupportsShouldProcess with ConfirmImpact High' {
        $attr = (Get-Command Update-WoscapBenchmark).ScriptBlock.Attributes |
            Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
        $attr.SupportsShouldProcess | Should -BeTrue
        $attr.ConfirmImpact         | Should -Be 'High'
    }

    It 'reports Updated with From/To when a newer revision resolves' {
        InModuleScope woscap -Parameters @{ V1 = $script:ZipV1; V2 = $script:ZipV2 } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-updc-' + [guid]::NewGuid().ToString('N'))
            try {
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"u1"' } } }
                    else { Copy-Item -LiteralPath $V1 -Destination $OutFile -Force }
                }
                $null = Save-WoscapStigContent -Benchmark 'Windows11' -Url 'https://disa/v1.zip' -AcceptDisaTerms -Destination $cache

                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"u1"' } } }
                    else { Copy-Item -LiteralPath $V2 -Destination $OutFile -Force }
                }
                $row = Update-WoscapBenchmark -Benchmark 'Windows11' -Url 'https://disa/v2.zip' -AcceptDisaTerms -Destination $cache -Confirm:$false
                $row.Status       | Should -Be 'Updated'
                $row.FromRevision | Should -Be '1'
                $row.ToRevision   | Should -Be '2'
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'reports AlreadyCurrent and does not re-promote when the revision is unchanged' {
        InModuleScope woscap -Parameters @{ V1 = $script:ZipV1 } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-updc-' + [guid]::NewGuid().ToString('N'))
            try {
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"u1"' } } }
                    else { Copy-Item -LiteralPath $V1 -Destination $OutFile -Force }
                }
                $p = Save-WoscapStigContent -Benchmark 'Windows11' -Url 'https://disa/v1.zip' -AcceptDisaTerms -Destination $cache
                Set-Content -Path (Join-Path (Split-Path $p -Parent) 'sentinel.txt') -Value 'keep'

                $row = Update-WoscapBenchmark -Benchmark 'Windows11' -Url 'https://disa/v1.zip' -AcceptDisaTerms -Destination $cache -Confirm:$false
                $row.Status | Should -Be 'AlreadyCurrent'
                (Join-Path (Split-Path $p -Parent) 'sentinel.txt') | Should -Exist
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'reports Updated when the same revision is re-released with different content' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures; Tmp = $script:Tmp } {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $mk = {
                param($marker, $zipPath)
                $src = Join-Path $Tmp ('urel-' + [guid]::NewGuid().ToString('N'))
                New-Item -ItemType Directory -Path $src | Out-Null
                $xml = (Get-Content (Join-Path $Fixtures 'sample-xccdf.xml') -Raw) + "<!-- $marker -->"
                Set-Content -Path (Join-Path $src 'U_MS_Windows_11_STIG_V1R1_Manual-xccdf.xml') -Value $xml -Encoding UTF8
                [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $zipPath)
            }
            $zipA = Join-Path $Tmp ('uA-' + [guid]::NewGuid().ToString('N') + '.zip'); & $mk 'A' $zipA
            $zipB = Join-Path $Tmp ('uB-' + [guid]::NewGuid().ToString('N') + '.zip'); & $mk 'B' $zipB
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-urel-' + [guid]::NewGuid().ToString('N'))
            try {
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"old"' } } }
                    else { Copy-Item -LiteralPath $zipA -Destination $OutFile -Force }
                }
                $null = Save-WoscapStigContent -Benchmark 'URel' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache

                # Re-release: same revision '1', different bytes, new ETag (so no short-circuit).
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"new"' } } }
                    else { Copy-Item -LiteralPath $zipB -Destination $OutFile -Force }
                }
                $row = Update-WoscapBenchmark -Benchmark 'URel' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache -Confirm:$false
                $row.Status     | Should -Be 'Updated'
                $row.ToRevision | Should -Be '1'
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'reports Failed with a reason when a benchmark cannot be resolved, without throwing' {
        InModuleScope woscap {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-updc-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path (Join-Path $cache 'Orphan') | Out-Null   # cached but unresolvable
            Set-Content -LiteralPath (Get-WoscapDisaMarkerPath -CacheRoot $cache) -Value 'x'
            try {
                $row = Update-WoscapBenchmark -Benchmark 'Orphan' -Destination $cache -Confirm:$false -WarningAction SilentlyContinue
                $row.Status | Should -Be 'Failed'
                $row.Reason | Should -Match '-Url'
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'bulk-refreshes every cached benchmark and isolates one failure from another' {
        InModuleScope woscap -Parameters @{ V1 = $script:ZipV1 } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-updc-' + [guid]::NewGuid().ToString('N'))
            try {
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"u1"' } } }
                    else { Copy-Item -LiteralPath $V1 -Destination $OutFile -Force }
                }
                $null = Save-WoscapStigContent -Benchmark 'Windows11' -Url 'https://disa/v1.zip' -AcceptDisaTerms -Destination $cache
                New-Item -ItemType Directory -Path (Join-Path $cache 'Orphan') | Out-Null

                # -AcceptDisaTerms so Save's terms gate is satisfied for both benchmarks without an
                # interactive prompt (it writes no marker). Windows11 re-resolves via the bundled
                # manifest (real Url) -> mocked download -> same revision -> AlreadyCurrent; Orphan
                # has no -Url/manifest/scrape -> resolver throws -> Failed. One failure is isolated.
                $rows = @(Update-WoscapBenchmark -AcceptDisaTerms -Destination $cache -Confirm:$false -WarningAction SilentlyContinue)
                ($rows | Where-Object Benchmark -eq 'Windows11').Status | Should -Be 'AlreadyCurrent'
                ($rows | Where-Object Benchmark -eq 'Orphan').Status    | Should -Be 'Failed'
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It '-WhatIf previews a single benchmark and performs zero network I/O' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-updc-' + [guid]::NewGuid().ToString('N'))
            try {
                # Seed a cached revision directly (no download) so FromRevision resolves and a
                # -Times 0 assertion cleanly proves the -WhatIf run itself did no network I/O.
                New-SeededBench -Cache $cache -Benchmark 'Windows11' -Revision '1' -Fixtures $Fixtures | Out-Null

                Mock Invoke-WebRequest          { throw 'network I/O must not happen under -WhatIf' }
                Mock Get-WoscapStigDownloadPage { throw 'scrape must not happen under -WhatIf' }

                $row = Update-WoscapBenchmark -Benchmark 'Windows11' -Url 'https://disa/v1.zip' -AcceptDisaTerms -Destination $cache -WhatIf
                $row.Status       | Should -Be 'WhatIf'
                $row.Benchmark    | Should -Be 'Windows11'
                $row.FromRevision | Should -Be '1'
                $row.ToRevision   | Should -Be ''
                Should -Invoke Invoke-WebRequest -Times 0
                Should -Invoke Get-WoscapStigDownloadPage -Times 0
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It '-WhatIf previews every cached benchmark in bulk mode with zero network I/O' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-updc-' + [guid]::NewGuid().ToString('N'))
            try {
                foreach ($b in 'Windows11','Edge') { New-SeededBench -Cache $cache -Benchmark $b -Revision '1' -Fixtures $Fixtures | Out-Null }

                Mock Invoke-WebRequest          { throw 'network I/O must not happen under -WhatIf' }
                Mock Get-WoscapStigDownloadPage { throw 'scrape must not happen under -WhatIf' }

                $rows = @(Update-WoscapBenchmark -AcceptDisaTerms -AllowScrape -Destination $cache -WhatIf)
                @($rows).Count | Should -Be 2
                ($rows | ForEach-Object Status | Sort-Object -Unique) | Should -Be 'WhatIf'
                Should -Invoke Invoke-WebRequest -Times 0
                Should -Invoke Get-WoscapStigDownloadPage -Times 0
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'rejects -Url without a single -Benchmark' {
        InModuleScope woscap {
            { Update-WoscapBenchmark -Url 'https://disa/x.zip' -Destination (Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid())) } |
                Should -Throw -ExpectedMessage '*-Url*single*'
        }
    }

    It 'returns nothing (no throw) when bulk mode finds an empty cache' {
        InModuleScope woscap {
            $result = @(Update-WoscapBenchmark -Destination (Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid())))
            $result | Should -HaveCount 0
        }
    }

    It 'reports the numerically-newest revision as FromRevision (10 > 2)' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-updc-' + [guid]::NewGuid().ToString('N'))
            try {
                # Seed revision folders '2' and '10' directly with valid sidecars so Get-WoscapBenchmark lists them.
                foreach ($rev in '2','10') { New-SeededBench -Cache $cache -Benchmark 'NumBench' -Revision $rev -Fixtures $Fixtures | Out-Null }
                # No -Url/manifest/scrape for NumBench -> Save throws -> Failed, but FromRevision is computed BEFORE the save.
                $row = Update-WoscapBenchmark -Benchmark 'NumBench' -Destination $cache -Confirm:$false -WarningAction SilentlyContinue
                $row.FromRevision | Should -Be '10'
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'reports AlreadyCurrent (not Updated) when a legacy sidecar is merely backfilled with identical content' {
        InModuleScope woscap -Parameters @{ V1 = $script:ZipV1 } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-leg-' + [guid]::NewGuid().ToString('N'))
            try {
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"e1"' } } }
                    else { Copy-Item -LiteralPath $V1 -Destination $OutFile -Force }
                }
                # Cache the benchmark, then downgrade its sidecar to a legacy shape (no etag/hash),
                # exactly as a cache created before this feature would look.
                $p = Save-WoscapStigContent -Benchmark 'Windows11' -Url 'https://disa/v1.zip' -AcceptDisaTerms -Destination $cache
                $sidecar = Join-Path (Split-Path $p -Parent) '.woscap-content.json'
                Set-Content -LiteralPath $sidecar -Value (@{
                    benchmark = 'Windows11'; revision = '1'; sourceUrl = 'https://disa/v1.zip'
                } | ConvertTo-Json)

                # Refresh with byte-identical content under a new etag: Save backfills the legacy
                # sidecar (empty -> hash) but the content did not change -> must be AlreadyCurrent.
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"e2"' } } }
                    else { Copy-Item -LiteralPath $V1 -Destination $OutFile -Force }
                }
                $row = Update-WoscapBenchmark -Benchmark 'Windows11' -Url 'https://disa/v1.zip' -AcceptDisaTerms -Destination $cache -Confirm:$false
                $row.Status     | Should -Be 'AlreadyCurrent'
                $row.ToRevision | Should -Be '1'
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'reports Updated when a legacy sidecar sees a genuine same-revision re-release' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures; Tmp = $script:Tmp } {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            # Two revision-'1' archives with different XCCDF content (marker A vs B).
            $mk = {
                param($marker, $zipPath)
                $src = Join-Path $Tmp ('lupd-' + [guid]::NewGuid().ToString('N'))
                New-Item -ItemType Directory -Path $src | Out-Null
                $xml = (Get-Content (Join-Path $Fixtures 'sample-xccdf.xml') -Raw) + "<!-- $marker -->"
                Set-Content -Path (Join-Path $src 'U_MS_Windows_11_STIG_V1R1_Manual-xccdf.xml') -Value $xml -Encoding UTF8
                [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $zipPath)
            }
            $zipA = Join-Path $Tmp ('luA-' + [guid]::NewGuid().ToString('N') + '.zip'); & $mk 'A' $zipA
            $zipB = Join-Path $Tmp ('luB-' + [guid]::NewGuid().ToString('N') + '.zip'); & $mk 'B' $zipB
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-lupd-' + [guid]::NewGuid().ToString('N'))
            try {
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"e1"' } } }
                    else { Copy-Item -LiteralPath $zipA -Destination $OutFile -Force }
                }
                $p = Save-WoscapStigContent -Benchmark 'LUpd' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache
                # Downgrade the sidecar to a legacy (pre-content-hash) shape.
                Set-Content -LiteralPath (Join-Path (Split-Path $p -Parent) '.woscap-content.json') -Value (@{
                    benchmark = 'LUpd'; revision = '1'; sourceUrl = 'https://disa/x.zip'
                } | ConvertTo-Json)

                # Genuine re-release: same revision '1', DIFFERENT content -> must report Updated even
                # though the pre-hash (legacy) before-hash comes from the file fallback.
                Mock Invoke-WebRequest {
                    if ($Method -eq 'Head') { [pscustomobject]@{ Headers = @{ ETag = '"e2"' } } }
                    else { Copy-Item -LiteralPath $zipB -Destination $OutFile -Force }
                }
                $row = Update-WoscapBenchmark -Benchmark 'LUpd' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $cache -Confirm:$false
                $row.Status     | Should -Be 'Updated'
                $row.ToRevision | Should -Be '1'
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

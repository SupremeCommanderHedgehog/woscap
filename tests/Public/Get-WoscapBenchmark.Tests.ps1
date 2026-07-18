BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-getbench-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Tmp | Out-Null
    $script:Cache = Join-Path $script:Tmp 'cache'

    $fixtures = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures'
    $good = Join-Path $script:Tmp 'goodsrc'; New-Item -ItemType Directory -Path $good | Out-Null
    Copy-Item (Join-Path $fixtures 'sample-xccdf.xml') (Join-Path $good 'U_MS_Windows_11_STIG_V1R1_Manual-xccdf.xml')
    $script:GoodZip = Join-Path $script:Tmp 'good.zip'
    [System.IO.Compression.ZipFile]::CreateFromDirectory($good, $script:GoodZip)
}
AfterAll {
    Remove-Module woscap -Force -ErrorAction SilentlyContinue
    Remove-Item $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Get-WoscapBenchmark' {
    It 'is exported as a public command' {
        (Get-Command Get-WoscapBenchmark -Module woscap -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }
    It 'returns nothing when the cache root does not exist' {
        $missing = Join-Path $script:Tmp ('noexist-' + [guid]::NewGuid().ToString('N'))
        @(Get-WoscapBenchmark -Destination $missing).Count | Should -Be 0
    }
    It 'rejects a -Benchmark that would traverse outside the cache root' {
        { Get-WoscapBenchmark -Benchmark '..\..\Windows' -Destination $script:Cache } | Should -Throw '*unsafe benchmark name*'
    }
    It 'lists a cached benchmark + revision with its xccdf path and sidecar metadata' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip; Cache = $script:Cache } {
            Mock Invoke-WebRequest { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            $saved = Save-WoscapStigContent -Benchmark 'Windows11' -Url 'https://disa/w.zip' -AcceptDisaTerms -Destination $Cache
        }
        $rows = @(Get-WoscapBenchmark -Destination $script:Cache)
        $rows.Count | Should -Be 1
        $rows[0].Benchmark | Should -Be 'Windows11'
        $rows[0].Revision  | Should -Be '1'
        $rows[0].SourceUrl | Should -Be 'https://disa/w.zip'
        $rows[0].Path      | Should -Exist
        (Split-Path $rows[0].Path -Leaf) | Should -BeLike '*_Manual-xccdf.xml'
    }
    It 'filters to a single benchmark when -Benchmark is given' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip; Cache = $script:Cache } {
            Mock Invoke-WebRequest { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            $null = Save-WoscapStigContent -Benchmark 'OtherBench' -Url 'https://disa/o.zip' -AcceptDisaTerms -Destination $Cache
        }
        @(Get-WoscapBenchmark -Destination $script:Cache).Count            | Should -BeGreaterThan 1
        $only = @(Get-WoscapBenchmark -Benchmark 'OtherBench' -Destination $script:Cache)
        $only.Count            | Should -Be 1
        $only[0].Benchmark     | Should -Be 'OtherBench'
    }
    It 'emits ContentHash from the sidecar contentSha256' {
        InModuleScope woscap {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-ch-' + [guid]::NewGuid().ToString('N'))
            try {
                # Get-WoscapBenchmark only requires a *_Manual-xccdf.xml to exist (it never parses
                # it), so a dummy file is enough — no fixture needed.
                $rd = Join-Path (Join-Path $cache 'HashBench') '1'
                New-Item -ItemType Directory -Path $rd -Force | Out-Null
                Set-Content -Path (Join-Path $rd 'U_x_Manual-xccdf.xml') -Value '<Benchmark/>'
                Set-Content -LiteralPath (Get-WoscapContentSidecarPath -RevisionDir $rd) -Value (@{
                    benchmark = 'HashBench'; revision = '1'; contentSha256 = 'DEADBEEF'
                } | ConvertTo-Json)

                $row = Get-WoscapBenchmark -Benchmark 'HashBench' -Destination $cache
                $row.ContentHash | Should -Be 'DEADBEEF'
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'falls back to hashing the XCCDF when a legacy sidecar has no contentSha256' {
        InModuleScope woscap {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-chf-' + [guid]::NewGuid().ToString('N'))
            try {
                $rd = Join-Path (Join-Path $cache 'LegacyHash') '1'
                New-Item -ItemType Directory -Path $rd -Force | Out-Null
                $xccdf = Join-Path $rd 'U_x_Manual-xccdf.xml'
                Set-Content -Path $xccdf -Value '<Benchmark/>'
                # Legacy sidecar: no contentSha256 -> ContentHash must be the file's hash, not ''.
                Set-Content -LiteralPath (Get-WoscapContentSidecarPath -RevisionDir $rd) -Value (@{
                    benchmark = 'LegacyHash'; revision = '1'
                } | ConvertTo-Json)

                $row = Get-WoscapBenchmark -Benchmark 'LegacyHash' -Destination $cache
                $row.ContentHash | Should -Be (Get-FileHash -LiteralPath $xccdf -Algorithm SHA256).Hash
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'skips a revision directory that has a sidecar but no XCCDF' {
        $c   = Join-Path $script:Tmp ('partial-' + [guid]::NewGuid().ToString('N'))
        $rev = Join-Path (Join-Path $c 'PartialBench') '9'
        New-Item -ItemType Directory -Path $rev | Out-Null
        Set-Content -LiteralPath (Join-Path $rev '.woscap-content.json') -Value '{"benchmark":"PartialBench","revision":"9"}'
        @(Get-WoscapBenchmark -Benchmark 'PartialBench' -Destination $c).Count | Should -Be 0
    }
}

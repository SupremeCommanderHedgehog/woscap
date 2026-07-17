BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-save-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Tmp | Out-Null
    $script:Cache = Join-Path $script:Tmp 'cache'

    $fixtures = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures'

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
            Mock Invoke-WebRequest { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }

            $p = Save-WoscapStigContent -Benchmark 'Windows11' -Url 'https://disa/test.zip' -AcceptDisaTerms -Destination $Cache

            $p | Should -Exist
            $p | Should -Match 'Windows11[\\/]1[\\/].*_Manual-xccdf\.xml$'   # revision folder = XCCDF version '1'
            (Split-Path $p -Leaf) | Should -BeLike '*_Manual-xccdf.xml'
            (Join-Path (Split-Path $p -Parent) '.woscap-content.json') | Should -Exist
            Should -Invoke Invoke-WebRequest -Times 1 -Exactly

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
            Mock Invoke-WebRequest { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            { Save-WoscapStigContent -Benchmark 'EvilBench' -Url 'https://disa/e.zip' -AcceptDisaTerms -Destination $Cache } |
                Should -Throw -ExpectedMessage '*unsafe*revision*'
            # nothing escaped the cache root
            (Join-Path (Split-Path $Cache -Parent) 'woscap-pwned') | Should -Not -Exist
        }
    }

    It 'rejects an unsafe -Benchmark name before downloading' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            Mock Invoke-WebRequest {}
            { Save-WoscapStigContent -Benchmark '..\..\evil' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $Cache } |
                Should -Throw -ExpectedMessage '*unsafe benchmark*'
            Should -Invoke Invoke-WebRequest -Times 0 -Exactly
        }
    }

    It 'refuses without -AcceptDisaTerms (declined) and never downloads' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            Mock Invoke-WebRequest {}
            Mock Get-WoscapDisaConsent { $false }
            { Save-WoscapStigContent -Benchmark 'Windows11' -Url 'https://disa/x.zip' -Destination $Cache -WarningAction SilentlyContinue } |
                Should -Throw -ExpectedMessage '*DISA*'
            Should -Invoke Invoke-WebRequest -Times 0 -Exactly
            (Get-WoscapDisaMarkerPath -CacheRoot $Cache) | Should -Not -Exist
        }
    }

    It 'proceeds without -AcceptDisaTerms when a persisted marker is present' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip } {
            Mock Invoke-WebRequest { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            Mock Get-WoscapDisaConsent { throw 'consent should not be requested when a marker exists' }
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-marker-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $cache | Out-Null
            Set-Content -LiteralPath (Get-WoscapDisaMarkerPath -CacheRoot $cache) -Value 'x'
            try {
                $p = Save-WoscapStigContent -Benchmark 'MarkerBench' -Url 'https://disa/x.zip' -Destination $cache
                $p | Should -Exist
                Should -Invoke Invoke-WebRequest -Times 1 -Exactly
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'interactive accept downloads AND persists a marker for next time' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip } {
            Mock Invoke-WebRequest { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
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
            Mock Invoke-WebRequest { throw 'network down' }
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
            Mock Invoke-WebRequest { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
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
            Mock Invoke-WebRequest {}
            { Save-WoscapStigContent -Benchmark 'UnlistedBench' -AcceptDisaTerms -Destination $Cache } |
                Should -Throw -ExpectedMessage '*-Url*'
            Should -Invoke Invoke-WebRequest -Times 0 -Exactly
        }
    }

    It 'fails fast on a non-Benchmark archive and leaves the cache clean' {
        InModuleScope woscap -Parameters @{ Zip = $script:BadZip; Cache = $script:Cache } {
            Mock Invoke-WebRequest { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            { Save-WoscapStigContent -Benchmark 'BadBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $Cache } |
                Should -Throw -ExpectedMessage '*Benchmark*'
            (Join-Path $Cache 'BadBench') | Should -Not -Exist
            @(Get-ChildItem -LiteralPath $Cache -Directory -Filter '.staging-*' -ErrorAction SilentlyContinue).Count | Should -Be 0
        }
    }

    It 'reuses a cached revision without re-promoting when -Force is absent' {
        InModuleScope woscap -Parameters @{ Zip = $script:GoodZip; Cache = $script:Cache } {
            Mock Invoke-WebRequest { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
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
            Mock Invoke-WebRequest { Copy-Item -LiteralPath $Zip -Destination $OutFile -Force }
            $p1 = Save-WoscapStigContent -Benchmark 'ForceBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $Cache
            $revDir = Split-Path $p1 -Parent
            Set-Content -Path (Join-Path $revDir 'sentinel.txt') -Value 'wipe'
            $p2 = Save-WoscapStigContent -Benchmark 'ForceBench' -Url 'https://disa/x.zip' -AcceptDisaTerms -Destination $Cache -Force
            $p2 | Should -Be $p1
            (Join-Path $revDir 'sentinel.txt') | Should -Not -Exist
            Should -Invoke Invoke-WebRequest -Times 2 -Exactly
        }
    }
}

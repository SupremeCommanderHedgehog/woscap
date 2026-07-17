BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Resolve-WoscapStigUrl' {
    It 'returns the operator-supplied -Url verbatim' {
        InModuleScope woscap {
            Resolve-WoscapStigUrl -Benchmark 'Windows11' -Url 'https://disa/x.zip' |
                Should -Be 'https://disa/x.zip'
        }
    }
    It 'throws a clear message mentioning -Url when neither -Url nor a manifest entry resolves' {
        InModuleScope woscap {
            { Resolve-WoscapStigUrl -Benchmark 'UnlistedBench' } |
                Should -Throw -ExpectedMessage '*-Url*'
        }
    }
    It 'falls back to the bundled manifest when -Url is omitted' {
        InModuleScope woscap {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-man-' + [guid]::NewGuid().ToString('N') + '.psd1')
            Set-Content -LiteralPath $tmp -Value "@{ TestBench = 'https://manifest/test.zip' }"
            try {
                Resolve-WoscapStigUrl -Benchmark 'TestBench' -ManifestPath $tmp |
                    Should -Be 'https://manifest/test.zip'
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
    It '-Url overrides a manifest entry for the same benchmark' {
        InModuleScope woscap {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-man-' + [guid]::NewGuid().ToString('N') + '.psd1')
            Set-Content -LiteralPath $tmp -Value "@{ TestBench = 'https://manifest/test.zip' }"
            try {
                Resolve-WoscapStigUrl -Benchmark 'TestBench' -Url 'https://override/win.zip' -ManifestPath $tmp |
                    Should -Be 'https://override/win.zip'
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'resolves the seeded Windows11 benchmark from the bundled manifest' {
        InModuleScope woscap {
            Resolve-WoscapStigUrl -Benchmark 'Windows11' | Should -Match 'Windows_11'
        }
    }
    It 'reads Url from a hashtable manifest entry' {
        InModuleScope woscap {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-man-' + [guid]::NewGuid().ToString('N') + '.psd1')
            Set-Content -LiteralPath $tmp -Value "@{ HashBench = @{ Url = 'https://manifest/hash.zip'; ScrapePattern = 'HashBench STIG' } }"
            try {
                Resolve-WoscapStigUrl -Benchmark 'HashBench' -ManifestPath $tmp |
                    Should -Be 'https://manifest/hash.zip'
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'does NOT scrape when -AllowScrape is absent, even with a ScrapePattern' {
        InModuleScope woscap {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-man-' + [guid]::NewGuid().ToString('N') + '.psd1')
            Set-Content -LiteralPath $tmp -Value "@{ ScrapeBench = @{ ScrapePattern = 'ScrapeBench STIG' } }"
            Mock Get-WoscapStigDownloadPage { throw 'must not be called' }
            try {
                { Resolve-WoscapStigUrl -Benchmark 'ScrapeBench' -ManifestPath $tmp } |
                    Should -Throw -ExpectedMessage '*-AllowScrape*'
                Should -Invoke Get-WoscapStigDownloadPage -Times 0 -Exactly
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'scrapes for the latest URL when -AllowScrape and a ScrapePattern are present' {
        InModuleScope woscap {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-man-' + [guid]::NewGuid().ToString('N') + '.psd1')
            Set-Content -LiteralPath $tmp -Value "@{ ScrapeBench = @{ ScrapePattern = 'ScrapeBench STIG' } }"
            Mock Get-WoscapStigDownloadPage { '<a href="https://disa/U_ScrapeBench_V1R3_STIG.zip">ScrapeBench STIG - Ver 1, Rel 3</a>' }
            try {
                Resolve-WoscapStigUrl -Benchmark 'ScrapeBench' -AllowScrape -ManifestPath $tmp |
                    Should -Be 'https://disa/U_ScrapeBench_V1R3_STIG.zip'
                Should -Invoke Get-WoscapStigDownloadPage -Times 1 -Exactly
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'prefers a scraped URL over the pinned manifest Url when -AllowScrape is set' {
        InModuleScope woscap {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-man-' + [guid]::NewGuid().ToString('N') + '.psd1')
            Set-Content -LiteralPath $tmp -Value "@{ BothBench = @{ Url = 'https://manifest/both.zip'; ScrapePattern = 'BothBench STIG' } }"
            Mock Get-WoscapStigDownloadPage { '<a href="https://disa/U_BothBench_V9R9_STIG.zip">BothBench STIG - Ver 9, Rel 9</a>' }
            try {
                Resolve-WoscapStigUrl -Benchmark 'BothBench' -AllowScrape -ManifestPath $tmp |
                    Should -Be 'https://disa/U_BothBench_V9R9_STIG.zip'
                Should -Invoke Get-WoscapStigDownloadPage -Times 1 -Exactly
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'falls back to the pinned manifest Url when the -AllowScrape scrape yields nothing' {
        InModuleScope woscap {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-man-' + [guid]::NewGuid().ToString('N') + '.psd1')
            Set-Content -LiteralPath $tmp -Value "@{ BothBench = @{ Url = 'https://manifest/both.zip'; ScrapePattern = 'BothBench STIG' } }"
            Mock Get-WoscapStigDownloadPage { '<html>no matching anchors here</html>' }
            try {
                Resolve-WoscapStigUrl -Benchmark 'BothBench' -AllowScrape -ManifestPath $tmp -WarningAction SilentlyContinue |
                    Should -Be 'https://manifest/both.zip'
                Should -Invoke Get-WoscapStigDownloadPage -Times 1 -Exactly
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
}

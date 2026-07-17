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
}

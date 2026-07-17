BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapStigManifest' {
    It 'loads the bundled manifest and includes the Windows11 pointer' {
        InModuleScope woscap {
            $m = Get-WoscapStigManifest
            $m | Should -BeOfType [hashtable]
            $m.ContainsKey('Windows11') | Should -BeTrue
            $m['Windows11'] | Should -Match 'Windows_11'
        }
    }
    It 'loads an explicit -Path manifest' {
        InModuleScope woscap {
            $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-man-' + [guid]::NewGuid().ToString('N') + '.psd1')
            Set-Content -LiteralPath $tmp -Value "@{ FooBench = 'https://m/foo.zip' }"
            try {
                $m = Get-WoscapStigManifest -Path $tmp
                $m['FooBench'] | Should -Be 'https://m/foo.zip'
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'returns an empty hashtable when the manifest file is missing' {
        InModuleScope woscap {
            $missing = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-nomanifest-' + [guid]::NewGuid().ToString('N') + '.psd1')
            $m = Get-WoscapStigManifest -Path $missing
            $m | Should -BeOfType [hashtable]
            $m.Count | Should -Be 0
        }
    }
}

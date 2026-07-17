BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Test-WoscapDisaTermsAccepted' {
    It 'is false when no marker exists under the cache root' {
        InModuleScope woscap {
            $root = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-mark-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $root | Out-Null
            try {
                Test-WoscapDisaTermsAccepted -CacheRoot $root | Should -BeFalse
            } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'is true once the marker file is present' {
        InModuleScope woscap {
            $root = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-mark-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $root | Out-Null
            try {
                Set-Content -LiteralPath (Get-WoscapDisaMarkerPath -CacheRoot $root) -Value 'x'
                Test-WoscapDisaTermsAccepted -CacheRoot $root | Should -BeTrue
            } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'derives the marker path under the cache root' {
        InModuleScope woscap {
            Get-WoscapDisaMarkerPath -CacheRoot 'C:\cache' | Should -Be (Join-Path 'C:\cache' '.woscap-disa-accepted')
        }
    }
}

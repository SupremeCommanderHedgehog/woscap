BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapContentCacheRoot' {
    It 'returns the -Destination as a normalized absolute path' {
        InModuleScope woscap {
            $d = Join-Path ([System.IO.Path]::GetTempPath()) 'woscap-cacheroot-test'
            Get-WoscapContentCacheRoot -Destination $d | Should -Be ([System.IO.Path]::GetFullPath($d))
        }
    }
    It 'defaults to a path under LOCALAPPDATA when no -Destination is given' {
        InModuleScope woscap {
            $root = Get-WoscapContentCacheRoot
            $root | Should -BeLike (Join-Path $env:LOCALAPPDATA 'woscap*content*')
        }
    }
    It 'is read-only: it does NOT create the directory' {
        InModuleScope woscap {
            $d = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-noexist-' + [guid]::NewGuid().ToString('N'))
            $null = Get-WoscapContentCacheRoot -Destination $d
            (Test-Path -LiteralPath $d) | Should -BeFalse
        }
    }
}

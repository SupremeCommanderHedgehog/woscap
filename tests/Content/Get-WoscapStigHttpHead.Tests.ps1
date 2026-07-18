BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapStigHttpHead' {
    It 'returns ETag and Last-Modified from the HEAD response headers' {
        InModuleScope woscap {
            Mock Invoke-WebRequest {
                [pscustomobject]@{ Headers = @{ ETag = '"abc123"'; 'Last-Modified' = 'Wed, 01 Jan 2025 00:00:00 GMT' } }
            } -ParameterFilter { $Method -eq 'Head' }

            $h = Get-WoscapStigHttpHead -Uri 'https://disa/x.zip'
            $h.ETag         | Should -Be '"abc123"'
            $h.LastModified | Should -Be 'Wed, 01 Jan 2025 00:00:00 GMT'
        }
    }

    It 'normalizes an array-valued header (Windows PowerShell 5.1 shape)' {
        InModuleScope woscap {
            Mock Invoke-WebRequest {
                [pscustomobject]@{ Headers = @{ ETag = @('"multi"'); 'Last-Modified' = @() } }
            } -ParameterFilter { $Method -eq 'Head' }

            $h = Get-WoscapStigHttpHead -Uri 'https://disa/x.zip'
            $h.ETag         | Should -Be '"multi"'
            $h.LastModified | Should -Be ''
        }
    }

    It 'fails open (returns $null) when the HEAD request throws' {
        InModuleScope woscap {
            Mock Invoke-WebRequest { throw 'HEAD not supported' } -ParameterFilter { $Method -eq 'Head' }
            Get-WoscapStigHttpHead -Uri 'https://disa/x.zip' | Should -BeNullOrEmpty
        }
    }
}

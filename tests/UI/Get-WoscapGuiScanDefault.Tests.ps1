BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapGuiScanDefault' {
    It 'reads ThrottleLimit from Invoke-WoscapScan''s own parameter default' {
        InModuleScope woscap {
            (Get-WoscapGuiScanDefault).ThrottleLimit | Should -Be 8
        }
    }
    It 'returns an int' {
        InModuleScope woscap {
            (Get-WoscapGuiScanDefault).ThrottleLimit | Should -BeOfType [int]
        }
    }
}

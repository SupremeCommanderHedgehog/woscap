BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Test-WoscapWow64Process' {
    It 'returns a bool matching the process and OS bitness' {
        InModuleScope woscap {
            $expected = [Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess
            $r = Test-WoscapWow64Process
            $r | Should -BeOfType [bool]
            $r | Should -Be $expected
        }
    }
    It 'defines the refusal message once' {
        InModuleScope woscap {
            $script:WoscapWow64RefusalMessage | Should -BeLike 'woscap: refusing to run from a 32-bit process on 64-bit Windows;*Sysnative*'
        }
    }
}

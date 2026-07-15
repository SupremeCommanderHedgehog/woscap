BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Test-WoscapSameHost' {
    It 'matches identical names case-insensitively' {
        InModuleScope woscap { Test-WoscapSameHost 'SRV01' 'srv01' | Should -BeTrue }
    }
    It 'matches a short name to its FQDN (either direction)' {
        InModuleScope woscap {
            Test-WoscapSameHost 'SRV01' 'srv01.corp.example' | Should -BeTrue
            Test-WoscapSameHost 'srv01.corp.example' 'SRV01' | Should -BeTrue
        }
    }
    It 'does not collapse distinct hosts sharing a leading label' {
        InModuleScope woscap { Test-WoscapSameHost 'web.east.corp' 'web.west.corp' | Should -BeFalse }
    }
    It 'compares IP literals exactly (no octet-prefix collision)' {
        InModuleScope woscap {
            Test-WoscapSameHost '10.0.0.5' '10.0.0.5'  | Should -BeTrue
            Test-WoscapSameHost '10.0.0.5' '10.0.0.50' | Should -BeFalse
        }
    }
    It 'returns false when either side is null or empty' {
        InModuleScope woscap {
            Test-WoscapSameHost '' 'SRV01'   | Should -BeFalse
            Test-WoscapSameHost 'SRV01' $null | Should -BeFalse
        }
    }
}

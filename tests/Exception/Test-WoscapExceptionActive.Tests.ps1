BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Test-WoscapExceptionActive' {
    It 'is active when there is no Expires' {
        InModuleScope woscap {
            Test-WoscapExceptionActive -Exception @{ Type = 'AcceptedRisk' } | Should -BeTrue
        }
    }
    It 'is active when Expires is in the future' {
        InModuleScope woscap {
            Test-WoscapExceptionActive -Exception @{ Expires = '2030-01-01' } -ReferenceDate ([datetime]'2026-07-11') | Should -BeTrue
        }
    }
    It 'is inactive (fail closed) when Expires is in the past' {
        InModuleScope woscap {
            Test-WoscapExceptionActive -Exception @{ Expires = '2026-01-01' } -ReferenceDate ([datetime]'2026-07-11') | Should -BeFalse
        }
    }
    It 'is inactive (fail closed) when Expires is unparseable' {
        InModuleScope woscap {
            Test-WoscapExceptionActive -Exception @{ Expires = 'not-a-date' } -ReferenceDate ([datetime]'2026-07-11') | Should -BeFalse
        }
    }
}

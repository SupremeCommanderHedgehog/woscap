BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Resolve-WoscapException' {
    It 'returns the exception when present and active' {
        InModuleScope woscap {
            $prof = @{ 'X' = @{ Type = 'NotApplicable'; Justification = 'j' } }
            (Resolve-WoscapException -StigId 'X' -ExceptionProfile $prof).Type | Should -Be 'NotApplicable'
        }
    }
    It 'returns $null when the STIG ID has no exception' {
        InModuleScope woscap {
            Resolve-WoscapException -StigId 'Y' -ExceptionProfile @{ 'X' = @{ Type = 'Exclude' } } | Should -BeNullOrEmpty
        }
    }
    It 'returns $null and warns when the exception is expired (fail closed)' {
        InModuleScope woscap {
            $prof = @{ 'X' = @{ Type = 'AcceptedRisk'; Expires = '2026-01-01' } }
            $result = Resolve-WoscapException -StigId 'X' -ExceptionProfile $prof -ReferenceDate ([datetime]'2026-07-11') -WarningAction SilentlyContinue
            $result | Should -BeNullOrEmpty
        }
    }
    It 'ignores a malformed (non-hashtable) entry (fail closed, no throw)' {
        InModuleScope woscap {
            $result = Resolve-WoscapException -StigId 'X' -ExceptionProfile @{ 'X' = 'not-a-table' } -WarningAction SilentlyContinue
            $result | Should -BeNullOrEmpty
        }
    }
}

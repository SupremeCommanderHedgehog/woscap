BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-RegValue' {
    It 'returns the named value when present' {
        InModuleScope woscap {
            Mock Get-ItemProperty { [pscustomobject]@{ EnableLUA = 1 } }
            Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' |
                Should -Be 1
        }
    }
    It 'returns $null when the key/value is missing (no throw)' {
        InModuleScope woscap {
            Mock Get-ItemProperty { throw 'not found' }
            Get-RegValue -Path 'HKLM:\Nope' -Name 'Missing' | Should -BeNullOrEmpty
        }
    }
}

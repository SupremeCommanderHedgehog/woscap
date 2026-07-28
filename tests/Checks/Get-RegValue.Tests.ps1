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
    It 'returns $null when the key is genuinely missing (no throw)' {
        InModuleScope woscap {
            Mock Get-ItemProperty { throw [System.Management.Automation.ItemNotFoundException]::new('no key') }
            $v = Get-RegValue -Path 'HKLM:\Nope' -Name 'Missing'
            $v | Should -BeNullOrEmpty
            Test-WoscapUnreadable -Value $v | Should -BeFalse -Because 'absent is real evidence, not a failed read'
        }
    }
    It 'returns $null when the value name is genuinely missing' {
        InModuleScope woscap {
            Mock Get-ItemProperty { throw [System.Management.Automation.PSArgumentException]::new('no property') }
            Test-WoscapUnreadable -Value (Get-RegValue -Path 'HKLM:\X' -Name 'Missing') | Should -BeFalse
        }
    }
    It 'returns the unreadable sentinel when the read fails for any other reason' {
        InModuleScope woscap {
            # A permission failure must not read as "absent", because
            # AbsentIsPass would score it compliant.
            Mock Get-ItemProperty { throw [System.Security.SecurityException]::new('access denied') }
            $v = Get-RegValue -Path 'HKLM:\SECURITY' -Name 'X'
            Test-WoscapUnreadable -Value $v | Should -BeTrue
            Get-WoscapUnreadableReason -Value $v | Should -Match 'access denied'
        }
    }
}

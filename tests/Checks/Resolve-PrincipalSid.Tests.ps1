BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Resolve-PrincipalSid' {
    It 'resolves <Name> to <Sid>' -TestCases @(
        @{ Name = 'Administrators';  Sid = 'S-1-5-32-544' }
        @{ Name = 'Users';           Sid = 'S-1-5-32-545' }
        @{ Name = 'LOCAL SERVICE';   Sid = 'S-1-5-19' }
        @{ Name = 'NETWORK SERVICE'; Sid = 'S-1-5-20' }
        @{ Name = 'SERVICE';         Sid = 'S-1-5-6' }
    ) {
        InModuleScope woscap -Parameters @{ Name = $Name; Sid = $Sid } {
            Resolve-PrincipalSid -Name $Name | Should -Be $Sid
        }
    }
    It 'trims surrounding whitespace' {
        InModuleScope woscap { Resolve-PrincipalSid -Name '  Administrators ' | Should -Be 'S-1-5-32-544' }
    }
    It 'returns $null for an unresolvable principal (fail closed)' {
        InModuleScope woscap {
            Resolve-PrincipalSid -Name 'NoSuchPrincipalXyZ123' | Should -BeNullOrEmpty
        }
    }
    # These assert the STATIC MAP, not NTAccount translation. The account
    # translation path is locale-dependent and unavailable off-domain, which
    # is the whole reason the map exists - so the fallback is mocked away and
    # only a map hit can satisfy these.
    Context 'well-known principals resolve without account translation' {
        BeforeEach {
            InModuleScope woscap { Mock ConvertTo-WoscapNtAccountSid { $null } }
        }
        It 'resolves Administrators' {
            InModuleScope woscap { Resolve-PrincipalSid -Name 'Administrators' | Should -Be 'S-1-5-32-544' }
        }
        It 'resolves Remote Desktop Users' {
            InModuleScope woscap { Resolve-PrincipalSid -Name 'Remote Desktop Users' | Should -Be 'S-1-5-32-555' }
        }
        It 'resolves Backup Operators' {
            InModuleScope woscap { Resolve-PrincipalSid -Name 'Backup Operators' | Should -Be 'S-1-5-32-551' }
        }
        It 'resolves Hyper-V Administrators' {
            InModuleScope woscap { Resolve-PrincipalSid -Name 'Hyper-V Administrators' | Should -Be 'S-1-5-32-578' }
        }
        It 'resolves the Local account group' {
            InModuleScope woscap { Resolve-PrincipalSid -Name 'Local account' | Should -Be 'S-1-5-113' }
        }
        It 'resolves NT VIRTUAL MACHINE\Virtual Machines' {
            InModuleScope woscap { Resolve-PrincipalSid -Name 'NT VIRTUAL MACHINE\Virtual Machines' | Should -Be 'S-1-5-83-0' }
        }
        It 'still returns null for a name that is neither well-known nor translatable' {
            InModuleScope woscap { Resolve-PrincipalSid -Name 'CONTOSO\SomeGroup' | Should -BeNullOrEmpty }
        }
    }
    It 'falls back to account translation for a name outside the map' {
        InModuleScope woscap {
            Mock ConvertTo-WoscapNtAccountSid { 'S-1-5-21-1-2-3-1000' }
            Resolve-PrincipalSid -Name 'CONTOSO\Domain Admins' | Should -Be 'S-1-5-21-1-2-3-1000'
        }
    }
}

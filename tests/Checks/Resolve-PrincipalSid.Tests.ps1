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
}

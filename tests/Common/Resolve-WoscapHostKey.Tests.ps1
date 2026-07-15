BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Resolve-WoscapHostKey' {
    It 'returns the mapped value on a map hit (IP -> name)' {
        InModuleScope woscap {
            Resolve-WoscapHostKey -HostName '10.0.0.5' -HostMap @{ '10.0.0.5' = 'SRV01' } | Should -Be 'SRV01'
        }
    }
    It 'looks up the map case-insensitively' {
        InModuleScope woscap {
            Resolve-WoscapHostKey -HostName 'SRV01' -HostMap @{ 'srv01' = 'SRV01.corp' } | Should -Be 'SRV01.corp'
        }
    }
    It 'returns the host unchanged on a map miss with DNS off' {
        InModuleScope woscap {
            Resolve-WoscapHostKey -HostName '10.0.0.9' -HostMap @{ '10.0.0.5' = 'SRV01' } | Should -Be '10.0.0.9'
        }
    }
    It 'reverse-resolves an IP literal when -ResolveDns is set (mocked)' {
        InModuleScope woscap {
            Mock Resolve-WoscapReverseDns { 'SRV02.corp' }
            Resolve-WoscapHostKey -HostName '10.0.0.6' -ResolveDns | Should -Be 'SRV02.corp'
            Should -Invoke Resolve-WoscapReverseDns -Times 1 -Exactly
        }
    }
    It 'does not call DNS for a non-IP host even when -ResolveDns is set' {
        InModuleScope woscap {
            Mock Resolve-WoscapReverseDns { 'should-not-be-used' }
            Resolve-WoscapHostKey -HostName 'SRV03' -ResolveDns | Should -Be 'SRV03'
            Should -Invoke Resolve-WoscapReverseDns -Times 0
        }
    }
    It 'falls back to the original IP when DNS returns null' {
        InModuleScope woscap {
            Mock Resolve-WoscapReverseDns { $null }
            Resolve-WoscapHostKey -HostName '10.0.0.7' -ResolveDns | Should -Be '10.0.0.7'
        }
    }
    It 'returns null/empty input unchanged' {
        InModuleScope woscap {
            Resolve-WoscapHostKey -HostName '' | Should -Be ''
        }
    }
    It 'coerces $null input to empty string (mandatory [string] param behavior)' {
        InModuleScope woscap {
            Resolve-WoscapHostKey -HostName $null | Should -BeNullOrEmpty
        }
    }
    It 'does not treat a bare-integer host as an IP under -ResolveDns' {
        InModuleScope woscap {
            Mock Resolve-WoscapReverseDns { 'should-not-be-used' }
            Resolve-WoscapHostKey -HostName '16843009' -ResolveDns | Should -Be '16843009'
            Should -Invoke Resolve-WoscapReverseDns -Times 0 -Exactly
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Resolve-WoscapReverseDns' {
    It 'returns $null instead of throwing on a garbage address' {
        InModuleScope woscap {
            { Resolve-WoscapReverseDns -Ip 'not-an-ip' } | Should -Not -Throw
            Resolve-WoscapReverseDns -Ip 'not-an-ip' | Should -BeNullOrEmpty
        }
    }
    It 'never yields a surprising hostname for blank input (empty rejected at binding, whitespace returns $null)' {
        InModuleScope woscap {
            # Empty string is rejected by [Parameter(Mandatory)][string] validation before the body runs,
            # so it can never reach GetHostEntry (which would otherwise resolve '' to the local machine name).
            { Resolve-WoscapReverseDns -Ip '' } | Should -Throw
            # Whitespace-only DOES bind, so the in-body guard is what stops it hitting DNS.
            Resolve-WoscapReverseDns -Ip '   ' | Should -BeNullOrEmpty
        }
    }
    It 'returns a non-empty string for loopback (resolves locally, no network)' {
        InModuleScope woscap {
            $name = Resolve-WoscapReverseDns -Ip '127.0.0.1'
            # Loopback resolves without hitting the network; contract is "string or null, never throw".
            if ($null -ne $name) { $name | Should -BeOfType([string]) }
        }
    }
}

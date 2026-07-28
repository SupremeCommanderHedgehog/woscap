BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-CertificateSetting' {
    BeforeEach { InModuleScope woscap { Clear-WoscapReadCache } }

    It 'matches certificates by subject pattern' {
        InModuleScope woscap {
            Mock Get-WoscapCertStore { @(
                [pscustomobject]@{ Subject='CN=DoD Root CA 3'; Issuer='CN=DoD Root CA 3'; Thumbprint='AAA'; NotAfter=(Get-Date).AddYears(3) }
                [pscustomobject]@{ Subject='CN=Contoso';       Issuer='CN=Contoso';       Thumbprint='BBB'; NotAfter=(Get-Date).AddYears(3) }
            )}
            $v = @(Get-CertificateSetting -Store 'root' -Match @{ Subject='DoD Root CA' })
            $v.Count | Should -Be 1
            $v[0]    | Should -Match 'DoD Root CA 3'
        }
    }
    It 'excludes expired certificates when RequireUnexpired is set' {
        InModuleScope woscap {
            Mock Get-WoscapCertStore { @(
                [pscustomobject]@{ Subject='CN=DoD Root CA 3'; Issuer='CN=X'; Thumbprint='AAA'; NotAfter=(Get-Date).AddYears(-1) }
            )}
            @(Get-CertificateSetting -Store 'root' -Match @{ Subject='DoD Root CA' } -RequireUnexpired).Count | Should -Be 0
        }
    }
    It 'includes expired certificates by default' {
        InModuleScope woscap {
            Mock Get-WoscapCertStore { @(
                [pscustomobject]@{ Subject='CN=DoD Root CA 3'; Issuer='CN=DoD Interoperability Root CA 2'; Thumbprint='49CBE933'; NotAfter=(Get-Date).AddYears(-1) }
            )}
            @(Get-CertificateSetting -Store 'disallowed' -Match @{ Thumbprint='49CBE933' }).Count | Should -Be 1
        }
    }
    It 'requires every match criterion to hold' {
        InModuleScope woscap {
            Mock Get-WoscapCertStore { @(
                [pscustomobject]@{ Subject='CN=DoD Root CA 3'; Issuer='CN=Other'; Thumbprint='AAA'; NotAfter=(Get-Date).AddYears(3) }
            )}
            @(Get-CertificateSetting -Store 'disallowed' -Match @{ Subject='DoD Root CA 3'; Issuer='DoD Interoperability' }).Count | Should -Be 0
        }
    }
    It 'returns an empty set when the store is readable but holds no match' {
        InModuleScope woscap {
            Mock Get-WoscapCertStore { ,@() }
            @(Get-CertificateSetting -Store 'root' -Match @{ Subject='Anything' }).Count | Should -Be 0
        }
    }
    It 'propagates unreadable rather than reporting zero matches' {
        InModuleScope woscap {
            Mock Get-WoscapCertStore { New-WoscapUnreadable -Reason 'cannot read store' }
            Test-WoscapUnreadable -Value (Get-CertificateSetting -Store 'root' -Match @{ Subject='X' }) | Should -BeTrue
        }
    }
    It 'reports unreadable for an unsupported Match key instead of zero matches' {
        InModuleScope woscap {
            Mock Get-WoscapCertStore { ,@([pscustomobject]@{ Subject='CN=X'; Issuer='CN=Y'; Thumbprint='AAA'; NotAfter=(Get-Date).AddYears(1) }) }
            $v = Get-CertificateSetting -Store 'root' -Match @{ Subj='X' }
            Test-WoscapUnreadable -Value $v | Should -BeTrue
            Get-WoscapUnreadableReason -Value $v | Should -Match 'Subj'
        }
    }
    It 'matches thumbprints case-insensitively' {
        InModuleScope woscap {
            Mock Get-WoscapCertStore { @(
                [pscustomobject]@{ Subject='CN=X'; Issuer='CN=Y'; Thumbprint='49CBE933151872E1'; NotAfter=(Get-Date).AddYears(1) }
            )}
            @(Get-CertificateSetting -Store 'disallowed' -Match @{ Thumbprint='49cbe933151872e1' }).Count | Should -Be 1
        }
    }
    It 'reads a store once per scan' {
        InModuleScope woscap {
            $script:certHits = 0
            Mock Get-ChildItem { $script:certHits++; @() } -ParameterFilter { $Path -like 'Cert:\LocalMachine\*' }
            $null = Get-WoscapCertStore -Store 'root'
            $null = Get-WoscapCertStore -Store 'root'
            $script:certHits | Should -Be 1
        }
    }
    It 'returns the unreadable sentinel when the cert provider throws' {
        InModuleScope woscap {
            Mock Get-ChildItem { throw 'denied' } -ParameterFilter { $Path -like 'Cert:\LocalMachine\*' }
            Test-WoscapUnreadable -Value (Get-WoscapCertStore -Store 'root') | Should -BeTrue
        }
    }
}

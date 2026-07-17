BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Html = Get-Content -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/content/disa-downloads.html') -Raw
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Resolve-WoscapStigUrlFromPage' {
    It 'selects the highest Ver/Rel archive matching the pattern' {
        InModuleScope woscap -Parameters @{ Html = $script:Html } {
            Resolve-WoscapStigUrlFromPage -Html $Html -Pattern 'Microsoft Windows 11 STIG' |
                Should -Be 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R8_STIG.zip'
        }
    }
    It 'returns the Windows 10 archive when the pattern targets Windows 10' {
        InModuleScope woscap -Parameters @{ Html = $script:Html } {
            Resolve-WoscapStigUrlFromPage -Html $Html -Pattern 'Microsoft Windows 10 STIG' |
                Should -Be 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_10_V2R9_STIG.zip'
        }
    }
    It 'falls back to href V#R# when link text has no Ver/Rel' {
        InModuleScope woscap {
            $h = '<a href="https://example.com/U_MS_Win11_V3R1_STIG.zip">Download</a>'
            Resolve-WoscapStigUrlFromPage -Html $h -Pattern 'Win11' |
                Should -Be 'https://example.com/U_MS_Win11_V3R1_STIG.zip'
        }
    }
    It 'ignores a matching link with no parseable Ver/Rel (the SCAP row)' {
        InModuleScope woscap -Parameters @{ Html = $script:Html } {
            # Pattern matches both the V2R8 STIG and the version-less SCAP row; the SCAP row
            # must be skipped, so the STIG zip still wins.
            Resolve-WoscapStigUrlFromPage -Html $Html -Pattern 'Microsoft Windows 11' |
                Should -Be 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R8_STIG.zip'
        }
    }
    It 'warns and returns null when nothing matches' {
        InModuleScope woscap -Parameters @{ Html = $script:Html } {
            $result = Resolve-WoscapStigUrlFromPage -Html $Html -Pattern 'Red Hat Enterprise Linux' -WarningVariable w -WarningAction SilentlyContinue
            $result        | Should -BeNullOrEmpty
            ($w -join ' ') | Should -Match 'no archive'
        }
    }
    It 'warns and returns null on empty HTML' {
        InModuleScope woscap {
            $result = Resolve-WoscapStigUrlFromPage -Html '' -Pattern 'anything' -WarningVariable w -WarningAction SilentlyContinue
            $result        | Should -BeNullOrEmpty
            ($w -join ' ') | Should -Match 'empty'
        }
    }
    It 'warns and returns null on an invalid regex pattern' {
        InModuleScope woscap {
            Resolve-WoscapStigUrlFromPage -Html '<a href="x_V1R1_STIG.zip">x</a>' -Pattern 'Windows [11' -WarningAction SilentlyContinue |
                Should -BeNullOrEmpty
        }
    }
    It 'matches an archive href that carries a query string' {
        InModuleScope woscap {
            $h = '<a href="https://disa/U_MS_Win11_V1R1_STIG.zip?ver=abc">Win11 STIG - Ver 1, Rel 1</a>'
            Resolve-WoscapStigUrlFromPage -Html $h -Pattern 'Win11 STIG' |
                Should -Be 'https://disa/U_MS_Win11_V1R1_STIG.zip?ver=abc'
        }
    }
    It 'skips a row whose version overflows Int32 instead of throwing' {
        InModuleScope woscap {
            $h = '<a href="https://disa/bad_STIG.zip">Overflow STIG - Ver 9999999999, Rel 1</a>' + [Environment]::NewLine +
                 '<a href="https://disa/good_V1R2_STIG.zip">Overflow STIG - Ver 1, Rel 2</a>'
            { Resolve-WoscapStigUrlFromPage -Html $h -Pattern 'Overflow STIG' } | Should -Not -Throw
            Resolve-WoscapStigUrlFromPage -Html $h -Pattern 'Overflow STIG' |
                Should -Be 'https://disa/good_V1R2_STIG.zip'
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:PackPath = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'Content/Chrome'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Chrome content pack' {
    It 'loads and contains known Chrome STIG IDs' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            $p.Keys | Should -Contain 'DTBC-0011'   # PasswordManagerEnabled
            $p.Keys | Should -Contain 'DTBC-0068'   # DeveloperToolsAvailability
        }
    }
    It 'every descriptor is a Registry check under the Chrome policies key' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            foreach ($k in $p.Keys) {
                $d = $p[$k]
                $d.Type                    | Should -Be 'Registry'
                $d.Path                    | Should -Be 'HKLM:\SOFTWARE\Policies\Google\Chrome'
                $d.Name                    | Should -Not -BeNullOrEmpty
                $d.Operator                | Should -Be 'eq'
                $d.ContainsKey('Expected') | Should -BeTrue
                $d.Expected                | Should -BeOfType [int]
            }
        }
    }
    It 'spot-checks known descriptor values against the DISA Chrome STIG' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            $p['DTBC-0011'].Name     | Should -Be 'PasswordManagerEnabled'
            $p['DTBC-0011'].Expected | Should -Be 0            # false
            $p['DTBC-0068'].Name     | Should -Be 'DeveloperToolsAvailability'
            $p['DTBC-0068'].Expected | Should -Be 2
            $p['DTBC-0009'].Name     | Should -Be 'DefaultSearchProviderEnabled'
            $p['DTBC-0009'].Expected | Should -Be 1            # true
        }
    }
    It 'omits list/organization-specific/version rules (they stay Not_Reviewed)' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            $p.Keys | Should -Not -Contain 'DTBC-0005'   # ExtensionInstallBlocklist (list)
            $p.Keys | Should -Not -Contain 'DTBC-0038'   # SafeBrowsingProtectionLevel (1 or 2)
            $p.Keys | Should -Not -Contain 'DTBC-0050'   # version cross-reference
        }
    }
    It 'evaluates end-to-end through the engine against a mocked registry read' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            Mock Get-RegValue { 0 }
            (Test-Descriptor -Descriptor $p['DTBC-0011']).Result | Should -Be 'Pass'   # PasswordManagerEnabled=0
            Mock Get-RegValue { 1 }
            (Test-Descriptor -Descriptor $p['DTBC-0011']).Result | Should -Be 'Fail'
        }
    }
    It 'provides meaningful automated coverage (>=35 descriptors)' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            (Import-ContentPack -Path $PackPath).Keys.Count | Should -BeGreaterOrEqual 35
        }
    }
}

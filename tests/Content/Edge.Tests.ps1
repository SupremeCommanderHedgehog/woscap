BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:PackPath = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'Content/Edge'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Edge content pack' {
    It 'loads and contains known Edge STIG IDs' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            $p.Keys | Should -Contain 'EDGE-00-000050'   # SmartScreenEnabled
            $p.Keys | Should -Contain 'EDGE-00-000043'   # PasswordManagerEnabled
        }
    }
    It 'every descriptor is a Registry check under the Edge policies key with a Name and Expected' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            foreach ($k in $p.Keys) {
                $d = $p[$k]
                $d.Type     | Should -Be 'Registry'
                $d.Path     | Should -BeLike 'HKLM:\SOFTWARE\Policies\Microsoft\Edge*'
                $d.Name     | Should -Not -BeNullOrEmpty
                $d.Operator | Should -Be 'eq'
                $d.ContainsKey('Expected') | Should -BeTrue   # Expected present (0 is a valid value)
            }
        }
    }
    It 'spot-checks known descriptor values against the DISA Edge STIG' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            $p['EDGE-00-000050'].Name     | Should -Be 'SmartScreenEnabled'
            $p['EDGE-00-000050'].Expected | Should -Be 1
            $p['EDGE-00-000043'].Name     | Should -Be 'PasswordManagerEnabled'
            $p['EDGE-00-000043'].Expected | Should -Be 0
            $p['EDGE-00-000048'].Name     | Should -Be 'AuthSchemes'
            $p['EDGE-00-000048'].Expected | Should -Be 'ntlm,negotiate'   # REG_SZ string
        }
    }
    It 'evaluates end-to-end through the engine against a mocked registry read (compliant -> Pass)' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            Mock Get-RegValue { 1 }
            (Test-Descriptor -Descriptor $p['EDGE-00-000050']).Result | Should -Be 'Pass'   # SmartScreenEnabled=1
        }
    }
    It 'evaluates end-to-end against a mocked registry read (non-compliant -> Fail)' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            Mock Get-RegValue { 0 }
            (Test-Descriptor -Descriptor $p['EDGE-00-000050']).Result | Should -Be 'Fail'   # SmartScreenEnabled=0
        }
    }
    It 'provides meaningful automated coverage (>=50 descriptors)' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            (Import-ContentPack -Path $PackPath).Keys.Count | Should -BeGreaterOrEqual 50
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:PackPath = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'Content/Windows11'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Windows11 content pack' {
    It 'loads and contains known STIG IDs' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            $p.Keys | Should -Contain 'WN11-00-000165'
            $p.Keys | Should -Contain 'WN11-AU-000500'
            $p.Keys | Should -Contain 'WN11-00-000170'
        }
    }
    It 'every descriptor has a valid Type' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $valid = 'Registry','SecEdit','UserRight','AuditPolicy','Service','ScriptBlock'
            $p = Import-ContentPack -Path $PackPath
            foreach ($key in $p.Keys) { $p[$key].Type | Should -BeIn $valid }
        }
    }
    It 'the scriptblock override evaluates against a mocked registry read' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            Mock Get-RegValue { 4 }
            $p = Import-ContentPack -Path $PackPath
            (Test-Descriptor -Descriptor $p['WN11-00-000170']).Result | Should -Be 'Pass'
        }
    }
}

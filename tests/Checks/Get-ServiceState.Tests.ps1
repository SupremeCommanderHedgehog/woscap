BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-ServiceState' {
    It 'returns start mode and state for a service' {
        InModuleScope woscap {
            Mock Get-CimInstance { [pscustomobject]@{ Name='w32time'; StartMode='Auto'; State='Running' } }
            $s = Get-ServiceState -Name 'w32time'
            $s.StartMode | Should -Be 'Auto'
            $s.State     | Should -Be 'Running'
        }
    }
    It 'returns $null for a missing service' {
        InModuleScope woscap {
            Mock Get-CimInstance { $null }
            Get-ServiceState -Name 'nope' | Should -BeNullOrEmpty
        }
    }
}

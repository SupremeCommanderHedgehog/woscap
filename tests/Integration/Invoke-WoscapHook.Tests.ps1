BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Plugins = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/plugins'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-WoscapHook' {
    It 'invokes a hook and returns its result' {
        InModuleScope woscap -Parameters @{ Root = $script:Plugins } {
            $p = Import-WoscapPlugin -Path (Join-Path $Root 'Good')
            $r = Invoke-WoscapHook -Plugin $p -Hook 'Get-Targets' -Arguments @{ Source = 'x' }
            @($r) | Should -Be @('HOSTA', 'HOSTB')
        }
    }
    It 'returns null and warns when the hook is not offered by the plugin' {
        InModuleScope woscap -Parameters @{ Root = $script:Plugins } {
            $p = Import-WoscapPlugin -Path (Join-Path $Root 'Good')
            Invoke-WoscapHook -Plugin $p -Hook 'Export-Findings' -Arguments @{} -WarningAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }
    It 'isolates a throwing hook: warns and returns null, never rethrows' {
        InModuleScope woscap -Parameters @{ Root = $script:Plugins } {
            $p = Import-WoscapPlugin -Path (Join-Path $Root 'Throwing')
            { Invoke-WoscapHook -Plugin $p -Hook 'Get-Targets' -Arguments @{} -WarningAction SilentlyContinue } | Should -Not -Throw
            Invoke-WoscapHook -Plugin $p -Hook 'Get-Targets' -Arguments @{} 3>&1 | Should -Match 'boom from plugin'
        }
    }
}

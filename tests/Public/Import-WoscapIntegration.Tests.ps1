BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Plugins = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/plugins'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Import-WoscapIntegration' {
    It 'is exported as a public command' {
        Get-Command Import-WoscapIntegration -Module woscap | Should -Not -BeNullOrEmpty
    }
    It 'dispatches -Targets to the plugin Get-Targets hook' {
        $t = Import-WoscapIntegration -Integration 'Good' -PluginPath (Join-Path $script:Plugins 'Good') -Targets
        @($t) | Should -Be @('HOSTA', 'HOSTB')
    }
    It 'dispatches -Findings to the plugin Import-Findings hook' {
        $f = Import-WoscapIntegration -Integration 'Good' -PluginPath (Join-Path $script:Plugins 'Good') -Findings -Path 'ignored.xml'
        @($f).Count | Should -Be 1
        $f[0].Source | Should -Be 'Good'
    }
    It 'dispatches -Findings -CorrelateWith through Join-WoscapFinding (unified-view shape)' {
        $view = Import-WoscapIntegration -Integration 'Good' -PluginPath (Join-Path $script:Plugins 'Good') -Findings -Path 'x' -CorrelateWith @()
        $view.PSObject.Properties.Name | Should -Contain 'Results'
        $view.PSObject.Properties.Name | Should -Contain 'Findings'
        $view.PSObject.Properties.Name | Should -Contain 'Links'
    }
    It 'warns and returns nothing when the plugin cannot be loaded' {
        $r = Import-WoscapIntegration -Integration 'MissingHook' -PluginPath (Join-Path $script:Plugins 'MissingHook') -Targets -WarningAction SilentlyContinue
        $r | Should -BeNullOrEmpty
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Plugins = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/plugins'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Plugin conformance harness' {
    It 'passes for the Good fixture plugin' {
        InModuleScope woscap -Parameters @{ Root = $script:Plugins } {
            . (Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'helpers/Assert-WoscapPluginConformance.ps1')
            { Assert-WoscapPluginConformance -Path (Join-Path $Root 'Good') } | Should -Not -Throw
        }
    }
}

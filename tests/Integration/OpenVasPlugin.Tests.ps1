BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'helpers/Assert-WoscapPluginConformance.ps1')
    $repo = Split-Path $PSScriptRoot -Parent | Split-Path -Parent
    $script:PluginDir = Join-Path $repo 'Integrations/OpenVAS'
    $script:Report    = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/openvas/sample-report.xml'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'OpenVAS plugin' {
    It 'is conformant' {
        InModuleScope woscap -Parameters @{ Dir = $script:PluginDir } {
            . (Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'helpers/Assert-WoscapPluginConformance.ps1')
            { Assert-WoscapPluginConformance -Path $Dir } | Should -Not -Throw
        }
    }
    It 'ingests a report via Import-WoscapIntegration -Findings' {
        $f = Import-WoscapIntegration -Integration 'OpenVAS' -PluginPath $script:PluginDir -Findings -Path $script:Report
        @($f).Count | Should -Be 2
        $f[0].Source | Should -Be 'OpenVAS'
    }
    It 'produces a unified view when -CorrelateWith is supplied' {
        $rules = @([pscustomobject]@{ Host = '10.0.0.5'; RuleId = 'SV-1'; StigId = 'WN-1'; Cci = @('CCE-24913-4') })
        $view = Import-WoscapIntegration -Integration 'OpenVAS' -PluginPath $script:PluginDir -Findings -Path $script:Report -CorrelateWith $rules
        @($view.Links).Count | Should -Be 1
        $view.Links[0].MatchedOn | Should -Be 'CCE-24913-4'
    }
    It 'stubs Invoke-ExternalScan with a warning and null (no throw)' {
        InModuleScope woscap -Parameters @{ Dir = $script:PluginDir } {
            $p = Import-WoscapPlugin -Path $Dir
            { Invoke-WoscapHook -Plugin $p -Hook 'Invoke-ExternalScan' -Arguments @{ Config = @{} } -WarningAction SilentlyContinue } | Should -Not -Throw
            Invoke-WoscapHook -Plugin $p -Hook 'Invoke-ExternalScan' -Arguments @{ Config = @{} } -WarningAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }
}

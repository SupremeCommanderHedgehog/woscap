BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $repo = Split-Path $PSScriptRoot -Parent | Split-Path -Parent
    $script:PluginDir = Join-Path $repo 'Integrations/OpenVAS'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-WoscapIntegration' {
    It 'is exported by the module' {
        (Get-Command -Module woscap -Name Invoke-WoscapIntegration -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }
    It 'dispatches the Invoke-ExternalScan hook and returns its findings' {
        InModuleScope woscap {
            Mock Invoke-WoscapOpenVasScan { '<get_reports_response><report><results><result><host>h</host><threat>Low</threat><nvt oid="9"><name>n</name></nvt></result></results></report></get_reports_response>' }
        }
        $cred = [pscredential]::new('admin', (ConvertTo-SecureString 'pw' -AsPlainText -Force))
        $out = @(Invoke-WoscapIntegration -Integration 'OpenVAS' -PluginPath $script:PluginDir -Config @{
            Server = 'gvm'; Credential = $cred; Targets = @('h'); ScanConfigId = 'c'; ScannerId = 's' })
        $out.Count | Should -Be 1
        $out[0].Source | Should -Be 'OpenVAS'
    }
    It 'returns nothing (no throw) when the integration cannot be resolved' {
        $out = @(Invoke-WoscapIntegration -Integration 'DoesNotExist' -PluginPath (Join-Path ([System.IO.Path]::GetTempPath()) 'nope') -WarningAction SilentlyContinue)
        $out.Count | Should -Be 0
    }
}

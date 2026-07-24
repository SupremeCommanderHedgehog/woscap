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
    It 'Invoke-ExternalScan runs a live scan and normalizes the report' {
        InModuleScope woscap -Parameters @{ Dir = $script:PluginDir } {
            $p = Import-WoscapPlugin -Path $Dir
            Mock Invoke-WoscapOpenVasScan { '<get_reports_response><report><results><result><host>10.0.0.5</host><threat>High</threat><nvt oid="1.2.3"><name>x</name></nvt></result></results></report></get_reports_response>' }
            $cred = [pscredential]::new('admin', (ConvertTo-SecureString 'pw' -AsPlainText -Force))
            $findings = @(Invoke-WoscapHook -Plugin $p -Hook 'Invoke-ExternalScan' -Arguments @{ Config = @{
                Server = 'gvm'; Credential = $cred; Targets = @('10.0.0.5'); ScanConfigId = 'c'; ScannerId = 's' } })
            $findings.Count | Should -Be 1
            $findings[0].Source | Should -Be 'OpenVAS'
            $findings[0].Host   | Should -Be '10.0.0.5'
        }
    }
    It 'Invoke-ExternalScan coerces string config and forwards optional params' {
        InModuleScope woscap -Parameters @{ Dir = $script:PluginDir } {
            $p = Import-WoscapPlugin -Path $Dir
            Mock Invoke-WoscapOpenVasScan {
                '<get_reports_response><report><results><result><host>h</host><threat>Low</threat><nvt oid="1"><name>n</name></nvt></result></results></report></get_reports_response>'
            } -ParameterFilter {
                $Port -eq 9391 -and $PollSeconds -eq 5 -and $SkipCertificateCheck -eq $false -and $RequestTimeoutMs -eq 45000
            }
            $cred = [pscredential]::new('admin', (ConvertTo-SecureString 'pw' -AsPlainText -Force))
            $out = @(Invoke-WoscapHook -Plugin $p -Hook 'Invoke-ExternalScan' -Arguments @{ Config = @{
                Server = 'gvm'; Credential = $cred; Targets = @('h'); ScanConfigId = 'c'; ScannerId = 's'
                Port = '9391'; PollSeconds = '5'; SkipCertificateCheck = 'false'; RequestTimeoutMs = '45000' } })
            $out.Count | Should -Be 1
            Should -Invoke Invoke-WoscapOpenVasScan -Times 1 -Exactly
        }
    }
    It 'Invoke-ExternalScan warns and returns empty when required config is missing' {
        InModuleScope woscap -Parameters @{ Dir = $script:PluginDir } {
            $p = Import-WoscapPlugin -Path $Dir
            $out = @(Invoke-WoscapHook -Plugin $p -Hook 'Invoke-ExternalScan' -Arguments @{ Config = @{ Server = 'gvm' } } -WarningAction SilentlyContinue)
            $out.Count | Should -Be 0
        }
    }
    It 'Invoke-ExternalScan returns empty (no throw) when the scan yields no report' {
        InModuleScope woscap -Parameters @{ Dir = $script:PluginDir } {
            $p = Import-WoscapPlugin -Path $Dir
            Mock Invoke-WoscapOpenVasScan { $null }
            $cred = [pscredential]::new('admin', (ConvertTo-SecureString 'pw' -AsPlainText -Force))
            $out = @(Invoke-WoscapHook -Plugin $p -Hook 'Invoke-ExternalScan' -Arguments @{ Config = @{
                Server = 'gvm'; Credential = $cred; Targets = @('h'); ScanConfigId = 'c'; ScannerId = 's' } } -WarningAction SilentlyContinue)
            $out.Count | Should -Be 0
        }
    }
}

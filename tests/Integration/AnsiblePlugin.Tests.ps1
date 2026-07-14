BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'helpers/Assert-WoscapPluginConformance.ps1')
    $repo = Split-Path $PSScriptRoot -Parent | Split-Path -Parent
    $script:PluginDir = Join-Path $repo 'Integrations/Ansible'
    $script:InvIni    = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/ansible/inventory.ini'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Ansible plugin' {
    It 'is conformant' {
        InModuleScope woscap -Parameters @{ Dir = $script:PluginDir } {
            . (Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'helpers/Assert-WoscapPluginConformance.ps1')
            { Assert-WoscapPluginConformance -Path $Dir } | Should -Not -Throw
        }
    }
    It 'Get-Targets returns the inventory hosts via Import-WoscapIntegration' {
        $t = Import-WoscapIntegration -Integration 'Ansible' -PluginPath $script:PluginDir -Targets -Source $script:InvIni
        $t | Should -Contain 'win01.example.com'
    }
    It 'New-Remediation writes a playbook from Open rules' {
        $failed = @([pscustomobject]@{ StigId = 'WN11-AU-000010'; Title = 'Credential Validation'; Status = 'Open' })
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("play-" + [System.Guid]::NewGuid() + ".yml")
        try {
            $out = Export-WoscapIntegration -Integration 'Ansible' -PluginPath $script:PluginDir -Result $failed -Remediation -Path $tmp
            $out | Should -Be $tmp
            Get-Content $tmp -Raw | Should -Match 'win_audit_policy_system'
        } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
    It 'New-Remediation still emits (no throw) for a result lacking a Title property' {
        $failed = @(
            [pscustomobject]@{ StigId = 'WN11-AU-000010'; Status = 'Open' } | Select-Object StigId, Status
        )
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("play-" + [System.Guid]::NewGuid() + ".yml")
        try {
            { Export-WoscapIntegration -Integration 'Ansible' -PluginPath $script:PluginDir -Result $failed -Remediation -Path $tmp } | Should -Not -Throw
            $out = Export-WoscapIntegration -Integration 'Ansible' -PluginPath $script:PluginDir -Result $failed -Remediation -Path $tmp
            $out | Should -Be $tmp
            Get-Content $tmp -Raw | Should -Match 'win_audit_policy_system'
        } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
    It 'writes the playbook as BOM-less UTF-8 (ansible-playbook cannot parse a BOM)' {
        $failed = @([pscustomobject]@{ StigId = 'WN11-AU-000010'; Title = 'Credential Validation'; Status = 'Open' })
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("play-" + [System.Guid]::NewGuid() + ".yml")
        try {
            $null = Export-WoscapIntegration -Integration 'Ansible' -PluginPath $script:PluginDir -Result $failed -Remediation -Path $tmp
            $bytes = [System.IO.File]::ReadAllBytes($tmp)
            $bytes[0] | Should -Not -Be 0xEF
        } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
    It 'Export-Findings writes an Ansible facts JSON artifact' {
        $res = @([pscustomobject]@{ Host = 'H'; StigId = 'S'; Status = 'Open'; Severity = 'high' })
        $out = Export-WoscapIntegration -Integration 'Ansible' -PluginPath $script:PluginDir -Result $res -Config @{ FactsPath = (Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString() + '.json')) }
        Test-Path $out.FactsPath | Should -BeTrue
        Remove-Item $out.FactsPath -Force -ErrorAction SilentlyContinue
    }
}

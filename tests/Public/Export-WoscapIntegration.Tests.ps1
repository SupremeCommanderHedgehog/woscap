BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Plugins = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/plugins'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Export-WoscapIntegration' {
    It 'is exported as a public command' {
        Get-Command Export-WoscapIntegration -Module woscap | Should -Not -BeNullOrEmpty
    }
    It 'dispatches results to Export-Findings by default' {
        $res = @([pscustomobject]@{ StigId = 'A' }, [pscustomobject]@{ StigId = 'B' })
        $out = Export-WoscapIntegration -Integration 'Exporter' -PluginPath (Join-Path $script:Plugins 'Exporter') -Result $res
        $out.Pushed | Should -Be 2
    }
    It 'dispatches to New-Remediation with -Remediation -Path' {
        $res = @([pscustomobject]@{ StigId = 'A' })
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("play-" + [System.Guid]::NewGuid() + ".yml")
        try {
            $p = Export-WoscapIntegration -Integration 'Exporter' -PluginPath (Join-Path $script:Plugins 'Exporter') -Result $res -Remediation -Path $tmp
            $p | Should -Be $tmp
            Get-Content $tmp -Raw | Should -Match 'playbook'
        } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

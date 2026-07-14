BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'helpers/Assert-WoscapPluginConformance.ps1')
    $repo = Split-Path $PSScriptRoot -Parent | Split-Path -Parent
    $script:PluginDir = Join-Path $repo 'Integrations/Zabbix'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Zabbix plugin' {
    It 'is conformant' {
        InModuleScope woscap -Parameters @{ Dir = $script:PluginDir } {
            . (Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'helpers/Assert-WoscapPluginConformance.ps1')
            { Assert-WoscapPluginConformance -Path $Dir } | Should -Not -Throw
        }
    }
    It 'Export-Findings sends one metric batch per host' {
        InModuleScope woscap -Parameters @{ Dir = $script:PluginDir } {
            $sent = [System.Collections.Generic.List[object]]::new()
            Mock Send-WoscapZabbixMetric { $sent.Add($HostName); $true }
            $p = Import-WoscapPlugin -Path $Dir
            $res = @(
                [pscustomobject]@{ Host = 'SRV01'; Status = 'Open'; Severity = 'high'; Exception = $null },
                [pscustomobject]@{ Host = 'SRV02'; Status = 'NotAFinding'; Severity = 'low'; Exception = $null }
            )
            $ok = Invoke-WoscapHook -Plugin $p -Hook 'Export-Findings' -Arguments @{ Result = $res; Config = @{ Server = 'zbx'; Port = 10051 } }
            $ok | Should -BeTrue
            $sent | Should -Contain 'SRV01'
            $sent | Should -Contain 'SRV02'
        }
    }
    It 'Get-Targets returns hosts from a mocked host.get' {
        InModuleScope woscap -Parameters @{ Dir = $script:PluginDir } {
            Mock Invoke-RestMethod { [pscustomobject]@{ result = @([pscustomobject]@{ host = 'ZBX-A' }, [pscustomobject]@{ host = 'ZBX-B' }) } }
            $p = Import-WoscapPlugin -Path $Dir
            $t = Invoke-WoscapHook -Plugin $p -Hook 'Get-Targets' -Arguments @{ Config = @{ ApiUrl = 'http://z/api'; Token = 't' } }
            @($t) | Should -Be @('ZBX-A', 'ZBX-B')
        }
    }
}

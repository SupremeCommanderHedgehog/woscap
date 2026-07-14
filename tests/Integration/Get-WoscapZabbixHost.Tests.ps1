BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapZabbixHost' {
    It 'returns host names on a successful result' {
        InModuleScope woscap {
            Mock Invoke-RestMethod { [pscustomobject]@{ result = @([pscustomobject]@{ host = 'ZBX-A' }, [pscustomobject]@{ host = 'ZBX-B' }) } }
            @(Get-WoscapZabbixHost -ApiUrl 'http://z/api' -Token 't') | Should -Be @('ZBX-A', 'ZBX-B')
        }
    }
    It 'handles a JSON-RPC error reply (no result member) without throwing and returns @()' {
        InModuleScope woscap {
            Mock Invoke-RestMethod {
                [pscustomobject]@{
                    jsonrpc = '2.0'
                    error   = [pscustomobject]@{ code = -32602; message = 'Invalid params.'; data = 'Session terminated.' }
                    id      = 1
                }
            }
            { Get-WoscapZabbixHost -ApiUrl 'http://z/api' -Token 't' -WarningAction SilentlyContinue } | Should -Not -Throw
            $result = Get-WoscapZabbixHost -ApiUrl 'http://z/api' -Token 't' -WarningVariable warnings -WarningAction SilentlyContinue
            @($result).Count | Should -Be 0
            ($warnings -join ' ') | Should -Match 'Invalid params'
        }
    }
}

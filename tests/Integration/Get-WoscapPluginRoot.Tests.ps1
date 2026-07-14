BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapPluginRoot' {
    It 'defaults to the bundled Integrations folder under the module root' {
        InModuleScope woscap {
            $root = Get-WoscapPluginRoot
            Split-Path $root -Leaf | Should -Be 'Integrations'
            $root | Should -Be (Join-Path $script:WoscapModuleRoot 'Integrations')
        }
    }
    It 'returns an override path unchanged when one is supplied' {
        InModuleScope woscap {
            Get-WoscapPluginRoot -Path 'C:\custom\plugins' | Should -Be 'C:\custom\plugins'
        }
    }
}

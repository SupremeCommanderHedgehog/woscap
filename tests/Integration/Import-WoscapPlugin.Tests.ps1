BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Plugins = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/plugins'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Import-WoscapPlugin' {
    It 'loads a conformant plugin into a loaded-plugin object' {
        InModuleScope woscap -Parameters @{ Root = $script:Plugins } {
            $p = Import-WoscapPlugin -Path (Join-Path $Root 'Good')
            $p.Name | Should -Be 'Good'
            $p.Version | Should -Be '1.0.0'
            @($p.Capabilities) | Should -Contain 'Get-Targets'
            $p.Hooks['Get-Targets'] | Should -BeOfType [scriptblock]
        }
    }
    It 'warns and returns null when the implementation file is missing' {
        InModuleScope woscap -Parameters @{ Root = $script:Plugins } {
            Import-WoscapPlugin -Path (Join-Path $Root 'NoImpl') -WarningAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }
    It 'warns and returns null when the implementation does not return a hashtable' {
        InModuleScope woscap -Parameters @{ Root = $script:Plugins } {
            Import-WoscapPlugin -Path (Join-Path $Root 'NoTable') -WarningAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }
    It 'rejects a plugin that exposes an undeclared hook' {
        InModuleScope woscap -Parameters @{ Root = $script:Plugins } {
            Import-WoscapPlugin -Path (Join-Path $Root 'Undeclared') -WarningAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }
    It 'rejects a plugin whose declared hook is absent from the table' {
        InModuleScope woscap -Parameters @{ Root = $script:Plugins } {
            Import-WoscapPlugin -Path (Join-Path $Root 'MissingHook') -WarningAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }
    It 'rejects a plugin that declares a hook not in the known-hook set' {
        InModuleScope woscap -Parameters @{ Root = $script:Plugins } {
            Import-WoscapPlugin -Path (Join-Path $Root 'UnknownHook') -WarningAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }
    It 'rejects a plugin whose hook value is not a scriptblock' {
        InModuleScope woscap -Parameters @{ Root = $script:Plugins } {
            Import-WoscapPlugin -Path (Join-Path $Root 'NonScriptblock') -WarningAction SilentlyContinue | Should -BeNullOrEmpty
        }
    }
    It 'reaches the precise "no Name or Capabilities" message when Name is omitted' {
        InModuleScope woscap -Parameters @{ Root = $script:Plugins } {
            Import-WoscapPlugin -Path (Join-Path $Root 'NoName') -WarningAction SilentlyContinue | Should -BeNullOrEmpty
            Import-WoscapPlugin -Path (Join-Path $Root 'NoName') 3>&1 | Should -Match 'no Name or Capabilities'
        }
    }
    It 'loads a plugin whose implementation emits stray output before the hashtable' {
        InModuleScope woscap -Parameters @{ Root = $script:Plugins } {
            $p = Import-WoscapPlugin -Path (Join-Path $Root 'StrayOutput')
            $p | Should -Not -BeNullOrEmpty
            $p.Name | Should -Be 'StrayOutput'
            $p.Hooks['Get-Targets'] | Should -BeOfType [scriptblock]
        }
    }
    It 'emits a warning (not an exception) on a malformed plugin' {
        InModuleScope woscap -Parameters @{ Root = $script:Plugins } {
            { Import-WoscapPlugin -Path (Join-Path $Root 'MissingHook') -WarningAction SilentlyContinue } | Should -Not -Throw
            Import-WoscapPlugin -Path (Join-Path $Root 'MissingHook') 3>&1 | Should -Match 'MissingHook'
        }
    }
}

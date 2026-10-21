BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Test-WoscapPluginConfigSchema' {
    It 'accepts a manifest without ConfigOptions' {
        InModuleScope woscap {
            @(Test-WoscapPluginConfigSchema -Manifest @{ Capabilities = @('Get-Targets') }).Count | Should -Be 0
        }
    }
    It 'accepts a valid schema with every type' {
        InModuleScope woscap {
            $m = @{ Capabilities = @('Get-Targets'); ConfigOptions = @(
                @{ Name = 'a'; Type = 'Text'; Hooks = @('Get-Targets'); Default = 'x'; Required = $true; Help = 'h' }
                @{ Name = 'b'; Type = 'Number'; Hooks = @('Get-Targets'); Default = 5 }
                @{ Name = 'c'; Type = 'Bool'; Hooks = @('Get-Targets'); Default = $false }
                @{ Name = 'd'; Type = 'Credential'; Hooks = @('Get-Targets') }
                @{ Name = 'e'; Type = 'Secret'; Hooks = @('Get-Targets') }
                @{ Name = 'f'; Type = 'List'; Hooks = @('Get-Targets'); Default = @('1', '2') }
                @{ Name = 'g'; Type = 'Table'; Hooks = @('Get-Targets'); Default = @{ k = 'v' } }
                @{ Name = 'h'; Type = 'Path'; Hooks = @('Get-Targets') }) }
            @(Test-WoscapPluginConfigSchema -Manifest $m).Count | Should -Be 0
        }
    }
    It 'rejects: <Why>' -ForEach @(
        @{ Why = 'non-hashtable entry'; Opt = 'oops' }
        @{ Why = 'missing Name'; Opt = @{ Type = 'Text'; Hooks = @('Get-Targets') } }
        @{ Why = 'empty Name'; Opt = @{ Name = ' '; Type = 'Text'; Hooks = @('Get-Targets') } }
        @{ Why = 'unknown Type'; Opt = @{ Name = 'a'; Type = 'Blob'; Hooks = @('Get-Targets') } }
        @{ Why = 'missing Type'; Opt = @{ Name = 'a'; Hooks = @('Get-Targets') } }
        @{ Why = 'missing Hooks'; Opt = @{ Name = 'a'; Type = 'Text' } }
        @{ Why = 'empty Hooks'; Opt = @{ Name = 'a'; Type = 'Text'; Hooks = @() } }
        @{ Why = 'hook not in Capabilities'; Opt = @{ Name = 'a'; Type = 'Text'; Hooks = @('Export-Findings') } }
        @{ Why = 'non-bool Required'; Opt = @{ Name = 'a'; Type = 'Text'; Hooks = @('Get-Targets'); Required = 'yes' } }
        @{ Why = 'Text Default not string'; Opt = @{ Name = 'a'; Type = 'Text'; Hooks = @('Get-Targets'); Default = 3 } }
        @{ Why = 'Number Default not number'; Opt = @{ Name = 'a'; Type = 'Number'; Hooks = @('Get-Targets'); Default = 'x' } }
        @{ Why = 'Bool Default not bool'; Opt = @{ Name = 'a'; Type = 'Bool'; Hooks = @('Get-Targets'); Default = 'true' } }
        @{ Why = 'List Default not array'; Opt = @{ Name = 'a'; Type = 'List'; Hooks = @('Get-Targets'); Default = 'x' } }
        @{ Why = 'Table Default not hashtable'; Opt = @{ Name = 'a'; Type = 'Table'; Hooks = @('Get-Targets'); Default = @(1) } }
        @{ Why = 'Credential with Default'; Opt = @{ Name = 'a'; Type = 'Credential'; Hooks = @('Get-Targets'); Default = 'x' } }
    ) {
        InModuleScope woscap -Parameters @{ Opt = $Opt } {
            $m = @{ Capabilities = @('Get-Targets'); ConfigOptions = @($Opt) }
            @(Test-WoscapPluginConfigSchema -Manifest $m).Count | Should -BeGreaterThan 0
        }
    }
    It 'rejects duplicate Names' {
        InModuleScope woscap {
            $m = @{ Capabilities = @('Get-Targets'); ConfigOptions = @(
                @{ Name = 'a'; Type = 'Text'; Hooks = @('Get-Targets') }
                @{ Name = 'a'; Type = 'Bool'; Hooks = @('Get-Targets') }) }
            @(Test-WoscapPluginConfigSchema -Manifest $m).Count | Should -BeGreaterThan 0
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapObjectProperty' {
    It 'reads an existing pscustomobject property' {
        InModuleScope woscap {
            $o = [pscustomobject]@{ Foo = 'bar' }
            Get-WoscapObjectProperty $o 'Foo' | Should -Be 'bar'
        }
    }
    It 'returns the default for a missing pscustomobject property without throwing under strict mode' {
        InModuleScope woscap {
            Set-StrictMode -Version Latest
            $o = [pscustomobject]@{ Foo = 'bar' }
            { Get-WoscapObjectProperty $o 'Missing' -Default 'D' } | Should -Not -Throw
            (Get-WoscapObjectProperty $o 'Missing' -Default 'D') | Should -Be 'D'
        }
    }
    It 'reads a hashtable key' {
        InModuleScope woscap {
            $h = @{ Alpha = 42 }
            Get-WoscapObjectProperty $h 'Alpha' | Should -Be 42
        }
    }
    It 'returns the default for a missing hashtable key' {
        InModuleScope woscap {
            $h = @{ Alpha = 42 }
            (Get-WoscapObjectProperty $h 'Beta' -Default 'none') | Should -Be 'none'
        }
    }
    It 'returns the default for a $null input' {
        InModuleScope woscap {
            (Get-WoscapObjectProperty $null 'Anything' -Default 'fallback') | Should -Be 'fallback'
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'ConvertTo-WoscapBool' {
    It 'treats the truthy string vocabulary as $true: <Value>' -ForEach @(
        @{ Value = '1' }, @{ Value = 'true' }, @{ Value = 'TRUE' }, @{ Value = 'True' }
        @{ Value = 'yes' }, @{ Value = 'YES' }, @{ Value = 'on' }, @{ Value = 'ON' }
        @{ Value = '  true  ' }, @{ Value = "`ttrue`n" }
    ) {
        InModuleScope woscap -Parameters @{ Value = $Value } {
            ConvertTo-WoscapBool $Value | Should -BeTrue
        }
    }

    It 'treats any other string as $false: <Name>' -ForEach @(
        @{ Name = 'false'; Value = 'false' }, @{ Name = '0'; Value = '0' }
        @{ Name = 'no'; Value = 'no' }, @{ Name = 'off'; Value = 'off' }
        @{ Name = 'empty'; Value = '' }, @{ Name = 'whitespace'; Value = '   ' }
        @{ Name = 'maybe'; Value = 'maybe' }, @{ Name = 'truthy-prefix'; Value = 'true-ish' }
        @{ Name = 'truthy-suffix'; Value = 'nope-yes' }, @{ Name = 'digit-2'; Value = '2' }
    ) {
        InModuleScope woscap -Parameters @{ Value = $Value } {
            ConvertTo-WoscapBool $Value | Should -BeFalse
        }
    }

    It 'passes real booleans through unchanged' {
        InModuleScope woscap {
            ConvertTo-WoscapBool $true  | Should -BeTrue
            ConvertTo-WoscapBool $false | Should -BeFalse
        }
    }

    It 'coerces non-string, non-boolean values the way [bool] does' {
        InModuleScope woscap {
            ConvertTo-WoscapBool 1    | Should -BeTrue
            ConvertTo-WoscapBool 0    | Should -BeFalse
            ConvertTo-WoscapBool $null | Should -BeFalse
        }
    }

    It 'always returns a [bool], never a match result or $null' {
        InModuleScope woscap {
            foreach ($v in @('yes', 'nope', $true, $null, 3)) {
                ConvertTo-WoscapBool $v | Should -BeOfType [bool]
            }
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'ConvertTo-WoscapStatus' {
    It 'maps <Result> to <Expected>' -TestCases @(
        @{ Result = 'Pass';        Expected = 'NotAFinding' }
        @{ Result = 'Fail';        Expected = 'Open' }
        @{ Result = 'NA';          Expected = 'Not_Applicable' }
        @{ Result = 'NotReviewed'; Expected = 'Not_Reviewed' }
        @{ Result = 'Error';       Expected = 'Not_Reviewed' }
    ) {
        InModuleScope woscap -Parameters @{ Result = $Result; Expected = $Expected } {
            ConvertTo-WoscapStatus -Result $Result | Should -Be $Expected
        }
    }
    It 'throws on an unknown result (fail closed)' {
        InModuleScope woscap {
            { ConvertTo-WoscapStatus -Result 'Bogus' } | Should -Throw
        }
    }
}

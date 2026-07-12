BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'ConvertTo-CklbStatus' {
    It 'maps <Status> to <Cklb>' -TestCases @(
        @{ Status = 'NotAFinding';    Cklb = 'not_a_finding' }
        @{ Status = 'Open';           Cklb = 'open' }
        @{ Status = 'Not_Applicable'; Cklb = 'not_applicable' }
        @{ Status = 'Not_Reviewed';   Cklb = 'not_reviewed' }
    ) {
        InModuleScope woscap -Parameters @{ Status = $Status; Cklb = $Cklb } {
            ConvertTo-CklbStatus -Status $Status | Should -Be $Cklb
        }
    }
    It 'throws on an unknown status (fail closed)' {
        InModuleScope woscap { { ConvertTo-CklbStatus -Status 'Bogus' } | Should -Throw }
    }
}

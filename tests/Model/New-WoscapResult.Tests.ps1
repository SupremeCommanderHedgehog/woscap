BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'New-WoscapResult' {
    It 'builds a result with all CKLB-aligned fields' {
        InModuleScope woscap {
            $r = New-WoscapResult -StigId 'WN11-AU-000010' -GroupId 'V-253283' `
                -RuleId 'SV-253283r829073_rule' -Severity 'medium' -Title 'Audit Credential Validation' `
                -Result 'Fail' -Expected 'Failure' -Observed 'No Auditing' -ComputerName 'PC1'
            $r.StigId    | Should -Be 'WN11-AU-000010'
            $r.Status    | Should -Be 'Open'
            $r.Severity  | Should -Be 'medium'
            $r.Observed  | Should -Be 'No Auditing'
            $r.PSObject.Properties.Name | Should -Contain 'FindingDetails'
            $r.PSObject.Properties.Name | Should -Contain 'Comments'
            $r.PSObject.Properties.Name | Should -Contain 'Cci'
        }
    }
    It 'survives Clixml serialization unchanged (plain data)' {
        InModuleScope woscap {
            $r = New-WoscapResult -StigId 'X' -Result 'Pass' -ComputerName 'PC1'
            $tmp = [System.IO.Path]::GetTempFileName()
            $r | Export-Clixml -Path $tmp
            $back = Import-Clixml -Path $tmp
            Remove-Item $tmp -Force
            $back.StigId | Should -Be 'X'
            $back.Status | Should -Be 'NotAFinding'
        }
    }
}

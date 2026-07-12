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
    It 'carries a GroupTitle (SRG) field distinct from Title' {
        InModuleScope woscap {
            $r = New-WoscapResult -StigId 'X' -Result 'Pass' -ComputerName 'PC1' `
                -Title 'Rule title' -GroupTitle 'SRG-OS-000001'
            $r.GroupTitle | Should -Be 'SRG-OS-000001'
            $r.Title      | Should -Be 'Rule title'
        }
    }
    It 'carries CheckText, FixText, and Discussion' {
        InModuleScope woscap {
            $r = New-WoscapResult -StigId 'X' -Result 'Pass' -ComputerName 'PC1' `
                -CheckText 'check here' -FixText 'fix here' -Discussion 'why here'
            $r.CheckText  | Should -Be 'check here'
            $r.FixText    | Should -Be 'fix here'
            $r.Discussion | Should -Be 'why here'
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
    It 'carries a supplied Exception record' {
        InModuleScope woscap {
            $ex = [pscustomobject]@{ Type = 'AcceptedRisk'; Justification = 'risk accepted' }
            $r = New-WoscapResult -StigId 'X' -Result 'Fail' -ComputerName 'PC1' -Exception $ex
            $r.Exception.Type          | Should -Be 'AcceptedRisk'
            $r.Exception.Justification | Should -Be 'risk accepted'
        }
    }
    It 'defaults Exception to $null when not supplied' {
        InModuleScope woscap {
            (New-WoscapResult -StigId 'X' -Result 'Pass' -ComputerName 'PC1').Exception | Should -BeNullOrEmpty
        }
    }
}

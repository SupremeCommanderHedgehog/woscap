BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'New-WoscapRemediationResult' {
    It 'builds a result with the expected shape and defaults' {
        InModuleScope woscap {
            $r = New-WoscapRemediationResult -StigId 'R-1' -Title 'Reg' -CheckType 'Registry' `
                -Action 'Set X = 1 (dword)' -State 'Applied' -After 'NotAFinding' -Detail ''
            $r.StigId    | Should -Be 'R-1'
            $r.Title     | Should -Be 'Reg'
            $r.CheckType | Should -Be 'Registry'
            $r.Action    | Should -Be 'Set X = 1 (dword)'
            $r.State     | Should -Be 'Applied'
            $r.Before    | Should -Be 'Open'
            $r.After     | Should -Be 'NotAFinding'
            $r.Host      | Should -Be $env:COMPUTERNAME
        }
    }
    It 'defaults After to an em dash when not supplied' {
        InModuleScope woscap {
            (New-WoscapRemediationResult -StigId 'M-1' -Title 'x' -CheckType '' -Action 'Manual' -State 'Manual').After | Should -Be ([char]0x2014)
        }
    }
    It 'rejects an invalid State' {
        InModuleScope woscap {
            { New-WoscapRemediationResult -StigId 'x' -Title 't' -CheckType '' -Action 'a' -State 'Bogus' } | Should -Throw
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'New-WoscapExceptionRecord' {
    It 'projects the provenance fields' {
        InModuleScope woscap {
            $rec = New-WoscapExceptionRecord -Exception @{ Type = 'Override'; Justification = 'org uses 15'; Author = 'jdoe'; Date = '2026-07-01'; Expires = '2027-01-01' }
            $rec.Type          | Should -Be 'Override'
            $rec.Justification | Should -Be 'org uses 15'
            $rec.Author        | Should -Be 'jdoe'
            $rec.Date          | Should -Be '2026-07-01'
            $rec.Expires       | Should -Be '2027-01-01'
        }
    }
    It 'fills absent optional fields with empty strings' {
        InModuleScope woscap {
            $rec = New-WoscapExceptionRecord -Exception @{ Type = 'Exclude' }
            $rec.Author  | Should -Be ''
            $rec.Expires | Should -Be ''
        }
    }
}

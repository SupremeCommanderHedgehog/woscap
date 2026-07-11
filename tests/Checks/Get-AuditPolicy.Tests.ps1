BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-AuditPolicy' {
    It 'returns the inclusion array for a subcategory' {
        InModuleScope woscap {
            Mock Invoke-AuditPol {
                "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting`nPC1,System,Logon,{g},Failure,"
            }
            Get-AuditPolicy -Subcategory 'Logon' | Should -Be @('Failure')
        }
    }
    It 'returns $null for an unknown subcategory' {
        InModuleScope woscap {
            Mock Invoke-AuditPol {
                "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting`nPC1,System,Logon,{g},Failure,"
            }
            Get-AuditPolicy -Subcategory 'Nope' | Should -BeNullOrEmpty
        }
    }
}

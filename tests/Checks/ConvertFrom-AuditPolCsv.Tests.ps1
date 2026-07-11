BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Csv = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
PC1,System,Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success and Failure,
PC1,System,Logon,{0cce9215-69ae-11d9-bed3-505054503030},Failure,
'@
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'ConvertFrom-AuditPolCsv' {
    It 'returns the inclusion setting split into an array' {
        InModuleScope woscap -Parameters @{ Csv = $script:Csv } {
            $p = ConvertFrom-AuditPolCsv -CsvText $Csv
            $p['Credential Validation'] | Should -Be @('Success','Failure')
        }
    }
    It 'handles a single-value setting' {
        InModuleScope woscap -Parameters @{ Csv = $script:Csv } {
            $p = ConvertFrom-AuditPolCsv -CsvText $Csv
            $p['Logon'] | Should -Be @('Failure')
        }
    }
}

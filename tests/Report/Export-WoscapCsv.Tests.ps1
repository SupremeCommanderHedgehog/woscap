BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Export-WoscapCsv' {
    It 'writes one row per result with a flattened Cci column' {
        InModuleScope woscap {
            $results = @(
                New-WoscapResult -StigId 'WN11-00-000165' -GroupId 'V-1' -RuleId 'SV-1r1_rule' -Severity 'medium' -Title 'SMB1' -Result 'Fail' -Observed 1 -Expected 0 -Cci @('CCI-1','CCI-2') -ComputerName 'PC1'
                New-WoscapResult -StigId 'WN11-AU-000500' -GroupId 'V-2' -RuleId 'SV-2r1_rule' -Severity 'low' -Title 'Log' -Result 'Pass' -ComputerName 'PC1'
            )
            $out = Join-Path ([System.IO.Path]::GetTempPath()) ("woscap-" + [System.Guid]::NewGuid() + ".csv")
            try {
                Export-WoscapCsv -Result $results -Path $out
                $rows = Import-Csv -LiteralPath $out
                $rows.Count | Should -Be 2
                ($rows | Where-Object StigId -eq 'WN11-00-000165').Status | Should -Be 'Open'
                ($rows | Where-Object StigId -eq 'WN11-00-000165').Cci    | Should -Be 'CCI-1;CCI-2'
            } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
        }
    }
}

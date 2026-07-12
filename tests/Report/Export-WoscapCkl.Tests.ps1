BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Export-WoscapCkl' {
    It 'writes a well-formed legacy CKL with mapped VULN entries' {
        InModuleScope woscap {
            $results = @(
                New-WoscapResult -StigId 'WN11-00-000165' -GroupId 'V-253283' -RuleId 'SV-253283r1_rule' -Severity 'medium' -Title 'SMB1 & <disabled>' -Result 'Fail' -Observed 1 -Expected 0 -Cci @('CCI-000366','CCI-000999') -ComputerName 'PC1' -Benchmark 'Microsoft Windows 11 STIG' -BenchmarkVersion '2' -CheckText 'reg check' -FixText 'disable smb1' -Discussion 'why' -FindingDetails 'found 1'
                New-WoscapResult -StigId 'WN11-AU-000500' -GroupId 'V-2' -RuleId 'SV-2r1_rule' -Severity 'low' -Title 'Log' -Result 'Pass' -ComputerName 'PC1' -Benchmark 'Microsoft Windows 11 STIG' -BenchmarkVersion '2'
            )
            $out = Join-Path ([System.IO.Path]::GetTempPath()) ("woscap-" + [System.Guid]::NewGuid() + ".ckl")
            try {
                Export-WoscapCkl -Result $results -Path $out
                [xml]$doc = Get-Content $out -Raw            # parses => well-formed XML (escaping worked)
                $doc.CHECKLIST.ASSET.HOST_NAME | Should -Be 'PC1'
                $vulns = @($doc.CHECKLIST.STIGS.iSTIG.VULN)
                $vulns.Count | Should -Be 2
                $v = $vulns | Where-Object { ($_.STIG_DATA | Where-Object VULN_ATTRIBUTE -eq 'Rule_Ver').ATTRIBUTE_DATA -eq 'WN11-00-000165' }
                $v.STATUS | Should -Be 'Open'
                ($v.STIG_DATA | Where-Object VULN_ATTRIBUTE -eq 'Vuln_Num').ATTRIBUTE_DATA  | Should -Be 'V-253283'
                ($v.STIG_DATA | Where-Object VULN_ATTRIBUTE -eq 'Rule_Title').ATTRIBUTE_DATA | Should -Be 'SMB1 & <disabled>'
                @($v.STIG_DATA | Where-Object VULN_ATTRIBUTE -eq 'CCI_REF').ATTRIBUTE_DATA   | Should -Contain 'CCI-000366'
                @($v.STIG_DATA | Where-Object VULN_ATTRIBUTE -eq 'CCI_REF').Count            | Should -Be 2
                $v.FINDING_DETAILS | Should -Be 'found 1'
                ($vulns | Where-Object { ($_.STIG_DATA | Where-Object VULN_ATTRIBUTE -eq 'Rule_Ver').ATTRIBUTE_DATA -eq 'WN11-AU-000500' }).STATUS | Should -Be 'NotAFinding'
            } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Export-WoscapCklb' {
    It 'writes a STIG Viewer 3 CKLB document with mapped rules' {
        InModuleScope woscap {
            $results = @(
                New-WoscapResult -StigId 'WN11-00-000165' -GroupId 'V-253283' -RuleId 'SV-253283r1_rule' -Severity 'medium' -Title 'SMB1 disabled' -Result 'Fail' -Observed 1 -Expected 0 -Cci @('CCI-000366') -ComputerName 'PC1' -Benchmark 'Microsoft Windows 11 STIG' -BenchmarkVersion '2' -CheckText 'reg check' -FixText 'disable smb1' -Discussion 'why' -FindingDetails 'found 1'
                New-WoscapResult -StigId 'WN11-AU-000500' -GroupId 'V-2' -RuleId 'SV-2r1_rule' -Severity 'low' -Title 'Log size' -Result 'Pass' -ComputerName 'PC1' -Benchmark 'Microsoft Windows 11 STIG' -BenchmarkVersion '2'
            )
            $out = Join-Path ([System.IO.Path]::GetTempPath()) ("woscap-" + [System.Guid]::NewGuid() + ".cklb")
            try {
                Export-WoscapCklb -Result $results -Path $out
                $doc = Get-Content $out -Raw | ConvertFrom-Json
                # @()-wrap every JSON array read: ConvertTo-Json can collapse a single-element
                # array (e.g. one stig entry) and PSCustomObject has no .Count on WPS 5.1.
                $doc.cklb_version           | Should -Be '1.0'
                $doc.target_data.host_name  | Should -Be 'PC1'
                @($doc.stigs).Count         | Should -Be 1
                $stig = @($doc.stigs)[0]
                $stig.stig_name             | Should -Be 'Microsoft Windows 11 STIG'
                @($stig.rules).Count        | Should -Be 2
                $open = @($stig.rules) | Where-Object rule_version -eq 'WN11-00-000165'
                $open.status                | Should -Be 'open'
                $open.group_id              | Should -Be 'V-253283'
                $open.rule_id               | Should -Be 'SV-253283r1_rule'
                $open.severity              | Should -Be 'medium'
                @($open.ccis)               | Should -Contain 'CCI-000366'
                $open.check_content         | Should -Be 'reg check'
                $open.fix_text              | Should -Be 'disable smb1'
                $open.finding_details       | Should -Be 'found 1'
                (@($stig.rules) | Where-Object rule_version -eq 'WN11-AU-000500').status | Should -Be 'not_a_finding'
            } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
        }
    }
}

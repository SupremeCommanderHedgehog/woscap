BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Fixture = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/sample-xccdf.xml'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Import-Xccdf' {
    It 'parses all rules from the benchmark' {
        InModuleScope woscap -Parameters @{ Fixture = $script:Fixture } {
            (Import-Xccdf -Path $Fixture).Count | Should -Be 3
        }
    }
    It 'extracts rule metadata fields' {
        InModuleScope woscap -Parameters @{ Fixture = $script:Fixture } {
            $r = Import-Xccdf -Path $Fixture | Where-Object StigId -eq 'WNTEST-00-000010'
            $r.GroupId  | Should -Be 'V-100001'
            $r.RuleId   | Should -Be 'SV-100001r1_rule'
            $r.Severity | Should -Be 'medium'
            $r.Title    | Should -Be 'Example registry rule must be configured.'
            $r.Cci      | Should -Contain 'CCI-000366'
            $r.Benchmark | Should -Be 'Test Windows STIG'
        }
    }
    It 'extracts the Group title (SRG) distinctly from the Rule title' {
        InModuleScope woscap -Parameters @{ Fixture = $script:Fixture } {
            $r = Import-Xccdf -Path $Fixture | Where-Object StigId -eq 'WNTEST-00-000010'
            $r.GroupTitle | Should -Be 'SRG-OS-000001'
            $r.GroupTitle | Should -Not -Be $r.Title
        }
    }
    It 'throws on a non-XCCDF document' {
        InModuleScope woscap {
            $tmp = [System.IO.Path]::GetTempFileName()
            Set-Content -Path $tmp -Value '<notabenchmark/>'
            try { { Import-Xccdf -Path $tmp } | Should -Throw -ExpectedMessage '*Benchmark*' }
            finally { Remove-Item $tmp -Force }
        }
    }
}

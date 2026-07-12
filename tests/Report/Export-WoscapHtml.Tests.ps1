BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Export-WoscapHtml' {
    It 'writes a self-contained HTML dashboard with counts and a row per rule' {
        InModuleScope woscap {
            $results = @(
                New-WoscapResult -StigId 'WN11-00-000165' -GroupId 'V-1' -RuleId 'SV-1r1_rule' -Severity 'high'   -Title 'SMB1 & <x>' -Result 'Fail' -ComputerName 'PC1' -Benchmark 'Microsoft Windows 11 STIG'
                New-WoscapResult -StigId 'WN11-AU-000500' -GroupId 'V-2' -RuleId 'SV-2r1_rule' -Severity 'low'    -Title 'Log' -Result 'Pass' -ComputerName 'PC1' -Benchmark 'Microsoft Windows 11 STIG'
                New-WoscapResult -StigId 'WN11-UR-000005' -GroupId 'V-3' -RuleId 'SV-3r1_rule' -Severity 'medium' -Title 'Right' -Result 'NotReviewed' -ComputerName 'PC1' -Benchmark 'Microsoft Windows 11 STIG'
            )
            $out = Join-Path ([System.IO.Path]::GetTempPath()) ("woscap-" + [System.Guid]::NewGuid() + ".html")
            try {
                Export-WoscapHtml -Result $results -Path $out
                $html = Get-Content $out -Raw
                $html | Should -BeLike '*<!DOCTYPE html>*'
                $html | Should -BeLike '*Microsoft Windows 11 STIG*'
                $html | Should -BeLike '*WN11-00-000165*'
                $html | Should -BeLike '*WN11-AU-000500*'
                $html | Should -BeLike '*WN11-UR-000005*'
                $html | Should -BeLike '*SMB1 &amp; &lt;x&gt;*'
                $html | Should -Not -BeLike '*SMB1 & <x>*'
                $html | Should -BeLike '*Open*'
                $html | Should -BeLike '*Not_Reviewed*'
                $html | Should -Not -BeLike '*http://*'
                $html | Should -Not -BeLike '*https://*'
            } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
        }
    }
}

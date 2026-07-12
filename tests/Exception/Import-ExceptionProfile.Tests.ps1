BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Fixture = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/exceptions.psd1'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Import-ExceptionProfile' {
    It 'loads a profile keyed by STIG ID' {
        InModuleScope woscap -Parameters @{ Fixture = $script:Fixture } {
            $p = Import-ExceptionProfile -Path $Fixture
            $p['WNTEST-00-000010'].Type | Should -Be 'NotApplicable'
            $p['WNTEST-00-000020'].Type | Should -Be 'AcceptedRisk'
            $p.Keys.Count | Should -Be 2
        }
    }
    It 'merges multiple profiles with later paths winning on collision' {
        InModuleScope woscap -Parameters @{ Fixture = $script:Fixture } {
            $overlay = Join-Path ([System.IO.Path]::GetTempPath()) ("ov-" + [System.Guid]::NewGuid() + ".psd1")
            Set-Content -LiteralPath $overlay -Value "@{ 'WNTEST-00-000010' = @{ Type = 'Exclude'; Justification = 'handled out of band' } }"
            try {
                $p = Import-ExceptionProfile -Path $Fixture, $overlay
                $p['WNTEST-00-000010'].Type | Should -Be 'Exclude'   # overlay wins
                $p['WNTEST-00-000020'].Type | Should -Be 'AcceptedRisk'
            } finally { Remove-Item $overlay -Force -ErrorAction SilentlyContinue }
        }
    }
    It 'throws on a missing profile path' {
        InModuleScope woscap { { Import-ExceptionProfile -Path 'C:\nope\missing.psd1' } | Should -Throw }
    }
}

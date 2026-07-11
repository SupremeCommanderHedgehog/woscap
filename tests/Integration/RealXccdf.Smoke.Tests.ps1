BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:RealXccdf = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) `
        'STIG/_extracted/U_MS_Windows_11_STIG_V2R8_Manual-xccdf.xml'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Real Windows 11 XCCDF smoke' -Skip:(-not (Test-Path (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'STIG/_extracted/U_MS_Windows_11_STIG_V2R8_Manual-xccdf.xml'))) {
    It 'parses the real benchmark into 256 rules' {
        InModuleScope woscap -Parameters @{ Xccdf = $script:RealXccdf } {
            (Import-Xccdf -Path $Xccdf).Count | Should -Be 256
        }
    }
    It 'runs a full scan and returns a result per rule' {
        $res = Invoke-WoscapScan -XccdfPath $script:RealXccdf -Benchmark Windows11 -Quiet
        @($res).Count | Should -Be 256
        ($res | Where-Object StigId -eq 'WN11-00-000165').Status | Should -BeIn @('Open','NotAFinding')
        ($res | Where-Object Status -eq 'Not_Reviewed').Count | Should -BeGreaterThan 200
    }
}

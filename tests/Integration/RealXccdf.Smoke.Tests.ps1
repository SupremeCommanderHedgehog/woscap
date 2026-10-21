BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:RealXccdf = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) `
        'STIG/_extracted/U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Real Windows 11 XCCDF smoke' -Skip:(-not (Test-Path (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'STIG/_extracted/U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml'))) {
    It 'parses the real benchmark into 257 rules' {
        InModuleScope woscap -Parameters @{ Xccdf = $script:RealXccdf } {
            (Import-Xccdf -Path $Xccdf).Count | Should -Be 257
        }
    }
    It 'runs a full scan and returns a result per rule' {
        $res = Invoke-WoscapScan -XccdfPath $script:RealXccdf -Benchmark Windows11 -Quiet
        @($res).Count | Should -Be 257
        ($res | Where-Object StigId -eq 'WN11-00-000165').Status | Should -BeIn @('Open','NotAFinding')
        ($res | Where-Object Status -eq 'Not_Reviewed').Count | Should -BeLessThan 160
    }
}

Describe 'Real Defender Firewall XCCDF smoke' -Skip:(-not (Test-Path (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'STIG/U_MS_Windows_Defender_Firewall_V2R2_STIG/U_MS_Windows_Defender_Firewall_V2R2_Manual_STIG/U_MS_Windows_Defender_Firewall_STIG_V2R2_Manual-xccdf.xml'))) {
    BeforeAll {
        $script:FirewallXccdf = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) `
            'STIG/U_MS_Windows_Defender_Firewall_V2R2_STIG/U_MS_Windows_Defender_Firewall_V2R2_Manual_STIG/U_MS_Windows_Defender_Firewall_STIG_V2R2_Manual-xccdf.xml'
    }
    It 'parses the real benchmark into 21 rules' {
        InModuleScope woscap -Parameters @{ Xccdf = $script:FirewallXccdf } {
            (Import-Xccdf -Path $Xccdf).Count | Should -Be 21
        }
    }
    It 'runs a read-only scan with every rule authored and none in Error' {
        $res = Invoke-WoscapScan -XccdfPath $script:FirewallXccdf -Benchmark DefenderFirewall -Quiet
        @($res).Count | Should -Be 21
        # WNFWA-000100 is Manual; off-domain it is NA, so Not_Reviewed is at most 1.
        @($res | Where-Object Status -eq 'Not_Reviewed').Count | Should -BeLessOrEqual 1
        @($res | Where-Object Status -eq 'Error') | Should -BeNullOrEmpty
        ($res | Where-Object StigId -eq 'WNFWA-000002').Status | Should -BeIn @('Open', 'NotAFinding')
    }
}

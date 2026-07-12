BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:RemoteHost = $env:WOSCAP_REMOTE_TESTHOST
    $script:Xccdf      = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/sample-xccdf.xml'
    $script:Pack       = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/contentpack'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Remote scan (live)' -Skip:([string]::IsNullOrWhiteSpace($env:WOSCAP_REMOTE_TESTHOST)) {
    It 'scans a real remote host and stamps its name on the results' {
        $res = Invoke-WoscapScan -XccdfPath $script:Xccdf -ContentPath $script:Pack -ComputerName $script:RemoteHost -Quiet
        @($res).Count      | Should -BeGreaterThan 0
        @($res.Host)       | Should -Contain $script:RemoteHost
    }
    It 'isolates an unreachable host into a single Not_Reviewed result' {
        $res = Invoke-WoscapScan -XccdfPath $script:Xccdf -ContentPath $script:Pack `
            -ComputerName $script:RemoteHost, 'woscap-does-not-exist.invalid' -Quiet -WarningAction SilentlyContinue
        $bad = @($res | Where-Object { $_.Host -eq 'woscap-does-not-exist.invalid' })
        @($bad).Count  | Should -Be 1
        $bad[0].Status | Should -Be 'Not_Reviewed'
    }
}

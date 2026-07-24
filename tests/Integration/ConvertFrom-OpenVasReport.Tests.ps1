BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Report = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/openvas/sample-report.xml'
    $script:Sparse = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/openvas/sparse-report.xml'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'ConvertFrom-OpenVasReport' {
    It 'parses each result into a normalized Finding' {
        InModuleScope woscap -Parameters @{ Report = $script:Report } {
            $f = @(ConvertFrom-OpenVasReport -Path $Report)
            $f.Count | Should -Be 2
            $f[0].Host | Should -Be '10.0.0.5'
            $f[0].Source | Should -Be 'OpenVAS'
            $f[0].Id | Should -Be '1.3.6.1.4.1.25623.1.0.900001'
            $f[0].Cve | Should -Contain 'CVE-2017-0143'
            $f[0].Cce | Should -Contain 'CCE-24913-4'
            $f[0].Severity | Should -Be 'high'
        }
    }
    It 'maps OpenVAS threat levels to the woscap severity vocabulary' {
        InModuleScope woscap -Parameters @{ Report = $script:Report } {
            $f = @(ConvertFrom-OpenVasReport -Path $Report)
            ($f | Where-Object Id -match '900002').Severity | Should -Be 'medium'
        }
    }
    It 'warns and returns empty on malformed XML' {
        InModuleScope woscap {
            $bad = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString() + '.xml')
            Set-Content -LiteralPath $bad -Value '<not-a-report>'
            try { @(ConvertFrom-OpenVasReport -Path $bad -WarningAction SilentlyContinue).Count | Should -Be 0 }
            finally { Remove-Item $bad -Force }
        }
    }
    It 'parses an in-memory report string via -Xml with the same shape as -Path' {
        InModuleScope woscap -Parameters @{ Report = $script:Report } {
            $xml = Get-Content -LiteralPath $Report -Raw
            $f = @(ConvertFrom-OpenVasReport -Xml $xml)
            $f.Count | Should -Be 2
            $f[0].Source | Should -Be 'OpenVAS'
            $f[0].Id | Should -Be '1.3.6.1.4.1.25623.1.0.900001'
            $f[0].Severity | Should -Be 'high'
        }
    }
    It 'warns and returns empty when -Xml is not well-formed' {
        InModuleScope woscap {
            $f = @(ConvertFrom-OpenVasReport -Xml '<not-a-report' -WarningAction SilentlyContinue)
            $f.Count | Should -Be 0
        }
    }
    It 'parses a sparse result (missing optional nodes) without throwing under StrictMode' {
        InModuleScope woscap -Parameters @{ Sparse = $script:Sparse } {
            { $null = @(ConvertFrom-OpenVasReport -Path $Sparse) } | Should -Not -Throw
            $f = @(ConvertFrom-OpenVasReport -Path $Sparse)
            $f.Count | Should -Be 1
            $f[0].Host | Should -Be '10.0.0.9'
            $f[0].Id | Should -Be '1.3.6.1.4.1.25623.1.0.900003'
            @($f[0].Cve).Count | Should -Be 0
            @($f[0].Cce).Count | Should -Be 0
            @($f[0].Cci).Count | Should -Be 0
            $f[0].Port | Should -BeNullOrEmpty
            $f[0].Description | Should -BeNullOrEmpty
            $f[0].Severity | Should -Be 'medium'
        }
    }
}

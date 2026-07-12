BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Export-WoscapResult' {
    BeforeAll {
        $script:Fixture = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/sample-xccdf.xml'
        $script:Pack    = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/contentpack'
        Mock -ModuleName woscap Get-RegValue { 1 }
        $script:Results = Invoke-WoscapScan -XccdfPath $script:Fixture -ContentPath $script:Pack -Quiet
    }
    It 'is exported as a public command' {
        Get-Command Export-WoscapResult -Module woscap | Should -Not -BeNullOrEmpty
    }
    It 'writes a cklb file' {
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ("woscap-" + [System.Guid]::NewGuid() + ".cklb")
        try {
            Export-WoscapResult -Result $script:Results -Format cklb -Path $out
            (Get-Content $out -Raw | ConvertFrom-Json).cklb_version | Should -Be '1.0'
        } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
    }
    It 'accepts pipeline input and writes csv' {
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ("woscap-" + [System.Guid]::NewGuid() + ".csv")
        try {
            $script:Results | Export-WoscapResult -Format csv -Path $out
            @(Import-Csv -LiteralPath $out).Count | Should -Be @($script:Results).Count
        } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
    }
    It 'writes an html file' {
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ("woscap-" + [System.Guid]::NewGuid() + ".html")
        try {
            Export-WoscapResult -Result $script:Results -Format html -Path $out
            (Get-Content $out -Raw) | Should -BeLike '*<!DOCTYPE html>*'
        } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
    }
    It 'writes a ckl file' {
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ("woscap-" + [System.Guid]::NewGuid() + ".ckl")
        try {
            Export-WoscapResult -Result $script:Results -Format ckl -Path $out
            ([xml](Get-Content $out -Raw)).CHECKLIST | Should -Not -BeNullOrEmpty
        } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
    }
    It 'rejects an unknown format' {
        { Export-WoscapResult -Result $script:Results -Format xlsx -Path 'x' } | Should -Throw
    }
}

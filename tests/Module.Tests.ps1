BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $ModuleRoot 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'woscap module' {
    It 'imports without error' {
        (Get-Module woscap) | Should -Not -BeNullOrEmpty
    }
    It 'requires PowerShell 5.1 or later' {
        $manifest = Import-PowerShellDataFile (Join-Path $ModuleRoot 'woscap.psd1')
        [version]$manifest.PowerShellVersion | Should -Be ([version]'5.1')
    }
    It 'exports no public functions yet' {
        (Get-Command -Module woscap).Count | Should -Be 0
    }
}

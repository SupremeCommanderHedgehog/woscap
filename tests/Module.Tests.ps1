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
    It 'exports only the intended public commands' {
        (Get-Command -Module woscap).Name | Sort-Object | Should -Be @('Export-WoscapIntegration','Export-WoscapResult','Get-WoscapBenchmark','Get-WoscapIntegration','Import-WoscapIntegration','Invoke-WoscapRemediation','Invoke-WoscapScan','Remove-WoscapBenchmark','Save-WoscapStigContent','Show-WoscapGui','Update-WoscapBenchmark')
    }
}

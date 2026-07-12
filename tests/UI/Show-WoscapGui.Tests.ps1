BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Show-WoscapGui' {
    It 'is exported by the module' {
        (Get-Command -Module woscap -Name Show-WoscapGui -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
    }
    It 'takes no mandatory parameters (it is a launcher)' {
        $cmd = Get-Command Show-WoscapGui
        @($cmd.Parameters.Values | Where-Object { $_.Attributes.Mandatory -contains $true }) | Should -BeNullOrEmpty
    }
}

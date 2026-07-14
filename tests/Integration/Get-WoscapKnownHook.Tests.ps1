BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapKnownHook' {
    It 'returns the five known hook names' {
        InModuleScope woscap {
            $hooks = @(Get-WoscapKnownHook)
            $hooks.Count | Should -Be 5
            $hooks | Should -Be @('Get-Targets','Import-Findings','Export-Findings','Invoke-ExternalScan','New-Remediation')
        }
    }
}

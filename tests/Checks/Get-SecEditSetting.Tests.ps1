BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-SecEditSetting' {
    It 'returns a System Access value' {
        InModuleScope woscap {
            Mock Invoke-SecEditExport { "[System Access]`r`nMinimumPasswordLength = 14" }
            Get-SecEditSetting -Name 'MinimumPasswordLength' | Should -Be '14'
        }
    }
    It 'returns $null when absent' {
        InModuleScope woscap {
            Mock Invoke-SecEditExport { "[System Access]`r`nPasswordComplexity = 1" }
            Get-SecEditSetting -Name 'MissingKey' | Should -BeNullOrEmpty
        }
    }
}

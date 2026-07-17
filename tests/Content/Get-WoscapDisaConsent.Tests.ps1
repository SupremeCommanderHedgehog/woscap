BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapDisaConsent' {
    It 'returns a boolean and never prompts on a non-interactive host' {
        InModuleScope woscap {
            # Force the non-interactive branch so this test can never block.
            Mock -CommandName Test-WoscapHostInteractive -MockWith { $false }
            Get-WoscapDisaConsent -Notice 'terms' | Should -BeFalse
        }
    }
    It 'is exposed as a mockable seam (callers can stub the decision)' {
        InModuleScope woscap {
            Mock -CommandName Get-WoscapDisaConsent -MockWith { $true }
            Get-WoscapDisaConsent -Notice 'terms' | Should -BeTrue
        }
    }
}

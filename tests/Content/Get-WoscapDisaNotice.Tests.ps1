BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapDisaNotice' {
    It 'returns the exact notice text Save-WoscapStigContent has always shown' {
        InModuleScope woscap {
            $expected = @('woscap does NOT bundle or redistribute DISA STIG content. This action downloads content',
                'on demand from a URL you supply (or a bundled best-effort pointer) into an operator-local',
                'cache. Your use of that content is governed by DISA''s own terms (public.cyber.mil), not',
                'this project.') -join "`n"
            ((Get-WoscapDisaNotice) -replace "`r`n", "`n") | Should -BeExactly $expected
        }
    }
    It 'returns a single string' {
        InModuleScope woscap { (Get-WoscapDisaNotice) | Should -BeOfType [string] }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapStigDownloadPage' {
    It 'returns the response Content as a string' {
        InModuleScope woscap {
            Mock Invoke-WebRequest { [pscustomobject]@{ Content = '<html>hi</html>' } }
            Get-WoscapStigDownloadPage | Should -Be '<html>hi</html>'
            Should -Invoke Invoke-WebRequest -Times 1 -Exactly
        }
    }
    It 'requests the supplied -Uri' {
        InModuleScope woscap {
            Mock Invoke-WebRequest { [pscustomobject]@{ Content = 'x' } } -ParameterFilter { $Uri -eq 'https://example/stigs' }
            Get-WoscapStigDownloadPage -Uri 'https://example/stigs' | Should -Be 'x'
            Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://example/stigs' }
        }
    }
}

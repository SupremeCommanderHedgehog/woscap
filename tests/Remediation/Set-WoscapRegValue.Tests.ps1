BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Set-WoscapRegValue' {
    It 'forwards path/name/value and maps dword to DWord (no real write)' {
        InModuleScope woscap {
            Mock Test-Path { $true }
            Mock New-Item {}
            Mock Set-ItemProperty {}
            Set-WoscapRegValue -Path 'HKLM:\SOFTWARE\Test' -Name 'Foo' -Data 1 -Kind 'dword'
            Should -Invoke New-Item -Exactly 0
            Should -Invoke Set-ItemProperty -Exactly 1 -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Test' -and $Name -eq 'Foo' -and $Value -eq 1 -and $Type -eq 'DWord'
            }
        }
    }
    It 'maps string kind to a String property' {
        InModuleScope woscap {
            Mock Test-Path { $true }
            Mock New-Item {}
            Mock Set-ItemProperty {}
            Set-WoscapRegValue -Path 'HKLM:\S' -Name 'N' -Data 'abc' -Kind 'string'
            Should -Invoke Set-ItemProperty -Exactly 1 -ParameterFilter { $Type -eq 'String' -and $Value -eq 'abc' }
        }
    }
    It 'creates the key first when it is absent' {
        InModuleScope woscap {
            Mock Test-Path { $false }
            Mock New-Item {}
            Mock Set-ItemProperty {}
            Set-WoscapRegValue -Path 'HKLM:\SOFTWARE\New' -Name 'N' -Data 1 -Kind 'dword'
            Should -Invoke New-Item -Exactly 1 -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\New' }
            Should -Invoke Set-ItemProperty -Exactly 1
        }
    }
}

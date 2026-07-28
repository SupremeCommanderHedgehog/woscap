BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-OptionalFeatureState' {
    BeforeEach { InModuleScope woscap { Clear-WoscapReadCache } }

    It 'reports Enabled for InstallState 1' {
        InModuleScope woscap {
            Mock Get-CimInstance { @([pscustomobject]@{ Name='SMB1Protocol'; InstallState=1 }) }
            Get-OptionalFeatureState -FeatureName 'SMB1Protocol' | Should -Be 'Enabled'
        }
    }
    It 'reports Disabled for InstallState 2' {
        InModuleScope woscap {
            Mock Get-CimInstance { @([pscustomobject]@{ Name='SMB1Protocol'; InstallState=2 }) }
            Get-OptionalFeatureState -FeatureName 'SMB1Protocol' | Should -Be 'Disabled'
        }
    }
    It 'reports Absent for a feature not present at all' {
        InModuleScope woscap {
            Mock Get-CimInstance { @([pscustomobject]@{ Name='Other'; InstallState=1 }) }
            Get-OptionalFeatureState -FeatureName 'SMB1Protocol' | Should -Be 'Absent'
        }
    }
    It 'matches a feature name by wildcard' {
        InModuleScope woscap {
            Mock Get-CimInstance { @([pscustomobject]@{ Name='MicrosoftWindowsPowerShellV2Root'; InstallState=1 }) }
            Get-OptionalFeatureState -FeatureName '*PowerShellV2*' | Should -Be 'Enabled'
        }
    }
    It 'reports Enabled when any matching feature is enabled' {
        InModuleScope woscap {
            Mock Get-CimInstance { @(
                [pscustomobject]@{ Name='MicrosoftWindowsPowerShellV2';     InstallState=2 }
                [pscustomobject]@{ Name='MicrosoftWindowsPowerShellV2Root'; InstallState=1 }
            )}
            Get-OptionalFeatureState -FeatureName '*PowerShellV2*' | Should -Be 'Enabled'
        }
    }
    It 'enumerates features once per scan' {
        InModuleScope woscap {
            $script:featHits = 0
            Mock Get-CimInstance { $script:featHits++; @([pscustomobject]@{ Name='A'; InstallState=1 }) }
            $null = Get-OptionalFeatureState -FeatureName 'A'
            $null = Get-OptionalFeatureState -FeatureName 'B'
            $script:featHits | Should -Be 1
        }
    }
    It 'reports unreadable when the class cannot be read' {
        InModuleScope woscap {
            # NOT the string 'Unknown': the documented idiom for these rules is
            # Operator='notin'; Expected=@('Enabled'), and 'Unknown' satisfies
            # that, so a placeholder scored an unread machine as compliant.
            Mock Get-CimInstance { throw 'no' }
            Test-WoscapUnreadable -Value (Get-OptionalFeatureState -FeatureName 'A') | Should -BeTrue
        }
    }
    It 'still reports Absent when the class reads cleanly but lacks the feature' {
        InModuleScope woscap {
            Mock Get-CimInstance { @([pscustomobject]@{ Name='Other'; InstallState=1 }) }
            Get-OptionalFeatureState -FeatureName 'SMB1Protocol' | Should -Be 'Absent'
        }
    }
}

Describe 'Test-PathPresence' {
    It 'reports presence' {
        InModuleScope woscap {
            Mock Test-Path { $true }
            Test-PathPresence -Path 'C:\Windows\System32\telnet.exe' | Should -BeTrue
        }
    }
    It 'reports absence' {
        InModuleScope woscap {
            Mock Test-Path { $false }
            Test-PathPresence -Path 'C:\Windows\System32\telnet.exe' | Should -BeFalse
        }
    }
    It 'reports unreadable when the check throws' {
        InModuleScope woscap {
            # Not $false: these rules are "this binary must not exist", so
            # absent-on-failure would pass an unexamined filesystem.
            Mock Test-Path { throw 'denied' }
            Test-WoscapUnreadable -Value (Test-PathPresence -Path 'C:\nope') | Should -BeTrue
        }
    }
    It 'expands environment variables in the path' {
        InModuleScope woscap {
            Mock Test-Path { $Path -eq (Join-Path $env:SystemRoot 'System32\tftp.exe') }
            Test-PathPresence -Path '%SystemRoot%\System32\tftp.exe' | Should -BeTrue
        }
    }
}

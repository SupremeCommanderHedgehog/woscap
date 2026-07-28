BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-LocalAccountSetting' {
    BeforeEach {
        InModuleScope woscap {
            Clear-WoscapReadCache
            Mock Get-WoscapLocalUserRaw {
                @(
                    [pscustomobject]@{ Name='Administrator'; Enabled=$true;  PasswordExpires=$true;  PasswordAgeDays=10;  LastLogonDays=1   }
                    [pscustomobject]@{ Name='Guest';         Enabled=$false; PasswordExpires=$true;  PasswordAgeDays=0;   LastLogonDays=999 }
                    [pscustomobject]@{ Name='svc';           Enabled=$true;  PasswordExpires=$false; PasswordAgeDays=400; LastLogonDays=200 }
                )
            }
        }
    }

    It 'lists enabled user names' {
        InModuleScope woscap {
            $v = @(Get-LocalAccountSetting -Scope User -Property EnabledNames)
            $v | Should -Contain 'Administrator'
            $v | Should -Contain 'svc'
            $v | Should -Not -Contain 'Guest'
        }
    }
    It 'lists enabled accounts whose password never expires' {
        InModuleScope woscap {
            @(Get-LocalAccountSetting -Scope User -Property NonExpiringNames) | Should -Be @('svc')
        }
    }
    It 'lists enabled accounts idle beyond a threshold' {
        InModuleScope woscap {
            @(Get-LocalAccountSetting -Scope User -Property StaleNames -ThresholdDays 35) | Should -Be @('svc')
        }
    }
    It 'excludes a disabled account from the stale list' {
        InModuleScope woscap {
            @(Get-LocalAccountSetting -Scope User -Property StaleNames -ThresholdDays 35) | Should -Not -Contain 'Guest'
        }
    }
    It 'returns the password age of a named account' {
        InModuleScope woscap {
            Get-LocalAccountSetting -Scope User -Name 'Administrator' -Property PasswordAgeDays | Should -Be 10
        }
    }
    It 'returns null for the password age of an unknown account' {
        InModuleScope woscap {
            Get-LocalAccountSetting -Scope User -Name 'nobody' -Property PasswordAgeDays | Should -BeNullOrEmpty
        }
    }
    It 'returns group members' {
        InModuleScope woscap {
            Mock Get-WoscapLocalGroupMemberRaw { @('WS\Administrator','WS\svc') } -ParameterFilter { $Name -eq 'Administrators' }
            @(Get-LocalAccountSetting -Scope Group -Name 'Administrators' -Property Members).Count | Should -Be 2
        }
    }
    It 'returns an empty member list for an empty group' {
        InModuleScope woscap {
            Mock Get-WoscapLocalGroupMemberRaw { @() } -ParameterFilter { $Name -eq 'Backup Operators' }
            @(Get-LocalAccountSetting -Scope Group -Name 'Backup Operators' -Property Members).Count | Should -Be 0
        }
    }
    It 'enumerates local users once per scan' {
        InModuleScope woscap {
            $script:userHits = 0
            Mock Get-WoscapLocalUserRaw { $script:userHits++; @() }
            $null = Get-LocalAccountSetting -Scope User -Property EnabledNames
            $null = Get-LocalAccountSetting -Scope User -Property NonExpiringNames
            $script:userHits | Should -Be 1
        }
    }
    It 'reports unreadable when the account enumeration fails' {
        InModuleScope woscap {
            # Not @(): an empty account list is compliant under setequals @(),
            # so a failed enumeration must not look like "no offending accounts".
            Mock Get-WoscapLocalUserRaw { throw 'denied' }
            Test-WoscapUnreadable -Value (Get-LocalAccountSetting -Scope User -Property EnabledNames) | Should -BeTrue
        }
    }
    It 'reports unreadable when the group bind fails' {
        InModuleScope woscap {
            Mock Get-WoscapAdsiObject { throw 'access denied' }
            $v = Get-LocalAccountSetting -Scope Group -Name 'Administrators' -Property Members
            Test-WoscapUnreadable -Value $v | Should -BeTrue
            Get-WoscapUnreadableReason -Value $v | Should -Match 'Administrators'
        }
    }
    It 'reports unreadable when a Group descriptor supplies no Name' {
        InModuleScope woscap {
            Test-WoscapUnreadable -Value (Get-LocalAccountSetting -Scope Group -Property Members) | Should -BeTrue
        }
    }
    It 'rejects a User scope asking for a Group-only projection' {
        InModuleScope woscap {
            # 'User'+'Members' is the natural typo for 'Group'+'Members'. It
            # used to fall through to $null and score Pass under subsetof.
            Test-WoscapUnreadable -Value (Get-LocalAccountSetting -Scope User -Property Members) | Should -BeTrue
        }
    }
    It 'rejects a Group scope asking for a User-only projection' {
        InModuleScope woscap {
            $v = Get-LocalAccountSetting -Scope Group -Name 'Administrators' -Property EnabledNames
            Test-WoscapUnreadable -Value $v | Should -BeTrue
        }
    }
    It 'surfaces a mismatched Scope/Property as Error, not Pass' {
        InModuleScope woscap {
            $d = @{ Type='LocalAccount'; Scope='User'; Property='Members'; Operator='subsetof'; Expected=@('Administrator') }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Error'
        }
    }
    It 'is caught at pack load time by the schema validator' {
        InModuleScope woscap {
            $d = @{ Type='LocalAccount'; Scope='User'; Property='Members'; Operator='subsetof'; Expected=@('Administrator') }
            @(Test-WoscapDescriptorSchema -Descriptor $d) | Should -Match 'incompatible Property'
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Test-AclCompliance' {
    It 'passes when only allowed principals hold access' {
        InModuleScope woscap {
            Mock Get-AclSetting { @(
                [pscustomobject]@{ Identity='NT AUTHORITY\SYSTEM';    Rights='FullControl'; Type='Allow' }
                [pscustomobject]@{ Identity='BUILTIN\Administrators'; Rights='FullControl'; Type='Allow' }
            )}
            $r = Test-AclCompliance -Path 'C:\x.evtx' -AllowedPrincipals @('NT AUTHORITY\SYSTEM','BUILTIN\Administrators')
            $r.Compliant | Should -BeTrue
        }
    }
    It 'fails and names the offending principal' {
        InModuleScope woscap {
            Mock Get-AclSetting { @(
                [pscustomobject]@{ Identity='NT AUTHORITY\SYSTEM'; Rights='FullControl'; Type='Allow' }
                [pscustomobject]@{ Identity='BUILTIN\Users';       Rights='FullControl'; Type='Allow' }
            )}
            $r = Test-AclCompliance -Path 'C:\x.evtx' -AllowedPrincipals @('NT AUTHORITY\SYSTEM')
            $r.Compliant | Should -BeFalse
            $r.Offenders | Should -Match 'BUILTIN\\Users'
        }
    }
    It 'ignores Deny aces' {
        InModuleScope woscap {
            Mock Get-AclSetting { @(
                [pscustomobject]@{ Identity='BUILTIN\Users'; Rights='FullControl'; Type='Deny' }
            )}
            (Test-AclCompliance -Path 'C:\x' -AllowedPrincipals @()).Compliant | Should -BeTrue
        }
    }
    It 'permits a non-allowed principal held to MaxRights' {
        InModuleScope woscap {
            Mock Get-RegistryAclSetting { @(
                [pscustomobject]@{ Identity='BUILTIN\Users'; Rights='ReadKey'; Type='Allow' }
            )}
            $r = Test-AclCompliance -Path 'HKLM:\SOFTWARE' -AllowedPrincipals @() -MaxRights @('ReadKey','ReadPermissions')
            $r.Compliant | Should -BeTrue
        }
    }
    It 'rejects a non-allowed principal exceeding MaxRights' {
        InModuleScope woscap {
            Mock Get-RegistryAclSetting { @(
                [pscustomobject]@{ Identity='BUILTIN\Users'; Rights='FullControl'; Type='Allow' }
            )}
            $r = Test-AclCompliance -Path 'HKLM:\SOFTWARE' -AllowedPrincipals @() -MaxRights @('ReadKey')
            $r.Compliant | Should -BeFalse
        }
    }
    It 'reads a registry path through the registry helper, not the file one' {
        InModuleScope woscap {
            Mock Get-RegistryAclSetting { ,@() }
            Mock Get-AclSetting { throw 'filesystem helper must not be used for HKLM:' }
            (Test-AclCompliance -Path 'HKLM:\SECURITY' -AllowedPrincipals @()).Compliant | Should -BeTrue
        }
    }
    It 'matches allowed principals case-insensitively' {
        InModuleScope woscap {
            Mock Get-AclSetting { @(
                [pscustomobject]@{ Identity='nt authority\system'; Rights='FullControl'; Type='Allow' }
            )}
            (Test-AclCompliance -Path 'C:\x' -AllowedPrincipals @('NT AUTHORITY\SYSTEM')).Compliant | Should -BeTrue
        }
    }
    It 'splits a comma-separated rights list before comparing' {
        InModuleScope woscap {
            Mock Get-AclSetting { @(
                [pscustomobject]@{ Identity='BUILTIN\Users'; Rights='ReadAndExecute, Synchronize'; Type='Allow' }
            )}
            $r = Test-AclCompliance -Path 'C:\x' -AllowedPrincipals @() -MaxRights @('ReadAndExecute','Synchronize')
            $r.Compliant | Should -BeTrue
        }
    }
    It 'accepts numeric generic-rights ACEs that Windows renders as bare integers' {
        InModuleScope woscap {
            # A stock C:\Windows ACL carries 'BUILTIN\Users | -1610612736'
            # (GENERIC_READ|GENERIC_EXECUTE) beside the readable entries. Before
            # normalization the integer matched nothing in MaxRights, so
            # WN11-00-000095 reported Open on an untouched install.
            Mock Get-AclSetting { ,@(
                [pscustomobject]@{ Identity='BUILTIN\Users'; Rights='-1610612736'; Type='Allow' }
            )}
            $r = Test-AclCompliance -Path 'C:\Windows' -AllowedPrincipals @() -MaxRights @('Read','ReadAndExecute','ExecuteFile','Synchronize')
            $r.Compliant | Should -BeTrue
        }
    }
    It 'still rejects a numeric ACE conferring more than MaxRights' {
        InModuleScope woscap {
            # 268435456 is GENERIC_ALL -> FullControl, which is real excess.
            Mock Get-AclSetting { ,@(
                [pscustomobject]@{ Identity='BUILTIN\Users'; Rights='268435456'; Type='Allow' }
            )}
            $r = Test-AclCompliance -Path 'C:\Windows' -AllowedPrincipals @() -MaxRights @('Read','ReadAndExecute')
            $r.Compliant | Should -BeFalse
        }
    }
    It 'matches an allowed principal by SID when the display name is localized' {
        InModuleScope woscap {
            # 'VORDEFINIERT\Administratoren' is the German rendering of
            # BUILTIN\Administrators. Name comparison made every ACE on a
            # non-English host an offender.
            Mock Get-AclSetting { ,@(
                [pscustomobject]@{ Identity='VORDEFINIERT\Administratoren'; Rights='FullControl'; Type='Allow' }
            )}
            Mock Resolve-PrincipalSid { 'S-1-5-32-544' }
            $r = Test-AclCompliance -Path 'C:\x' -AllowedPrincipals @('Administrators')
            $r.Compliant | Should -BeTrue
        }
    }
    It 'still flags an unresolvable principal holding excess rights' {
        InModuleScope woscap {
            Mock Get-AclSetting { ,@(
                [pscustomobject]@{ Identity='CONTOSO\Interns'; Rights='FullControl'; Type='Allow' }
            )}
            Mock Resolve-PrincipalSid { $null } -ParameterFilter { $Name -eq 'CONTOSO\Interns' }
            Mock Resolve-PrincipalSid { 'S-1-5-32-544' } -ParameterFilter { $Name -eq 'Administrators' }
            (Test-AclCompliance -Path 'C:\x' -AllowedPrincipals @('Administrators')).Compliant | Should -BeFalse
        }
    }
    It 'reports non-compliant when the path cannot be read' {
        InModuleScope woscap {
            Mock Get-AclSetting { $null }
            $r = Test-AclCompliance -Path 'C:\missing' -AllowedPrincipals @()
            $r.Compliant | Should -BeFalse
            $r.Offenders | Should -Match 'unreadable'
        }
    }
}

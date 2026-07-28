BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Test-Descriptor' {
    It 'passes a Registry descriptor when the value matches' {
        InModuleScope woscap {
            Mock Get-RegValue { 1 }
            $d = @{ Type='Registry'; Path='HKLM:\X'; Name='EnableLUA'; Operator='eq'; Expected=1 }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'fails a Registry descriptor when the value differs and records Observed' {
        InModuleScope woscap {
            Mock Get-RegValue { 0 }
            $d = @{ Type='Registry'; Path='HKLM:\X'; Name='EnableLUA'; Operator='eq'; Expected=1 }
            $r = Test-Descriptor -Descriptor $d
            $r.Result   | Should -Be 'Fail'
            $r.Observed | Should -Be 0
        }
    }
    It 'evaluates an AuditPolicy descriptor via includes' {
        InModuleScope woscap {
            Mock Get-AuditPolicy { @('Success','Failure') }
            $d = @{ Type='AuditPolicy'; Subcategory='Logon'; Operator='includes'; Expected='Failure' }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'runs a ScriptBlock descriptor (escape hatch)' {
        InModuleScope woscap {
            $d = @{ Type='ScriptBlock'; Script={ 'Pass' } }
            $r = Test-Descriptor -Descriptor $d
            $r.Result   | Should -Be 'Pass'
            $r.Observed | Should -Be 'Pass'
            $r.Expected | Should -BeNullOrEmpty
        }
    }
    It 'returns Error (fail closed) when the check throws' {
        InModuleScope woscap {
            Mock Get-RegValue { throw 'boom' }
            $d = @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Error'
        }
    }
    It 'returns Error (no unhandled throw) when Expected is omitted and the check throws' {
        InModuleScope woscap {
            Mock Get-RegValue { throw 'boom' }
            $d = @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq' }  # no Expected key
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Error'
        }
    }
    It 'returns Error when the target service is missing' {
        InModuleScope woscap {
            Mock Get-ServiceState { $null }
            $d = @{ Type='Service'; Name='nope'; Operator='eq'; Expected='Disabled' }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Error'
        }
    }
    It 'returns Error for an unknown descriptor Type' {
        InModuleScope woscap {
            (Test-Descriptor -Descriptor @{ Type='Bogus' }).Result | Should -Be 'Error'
        }
    }
    It 'normalizes an out-of-set ScriptBlock result to Error (fail closed)' {
        InModuleScope woscap {
            $d = @{ Type='ScriptBlock'; Script={ 'Yes' } }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Error'
        }
    }
    It 'UserRight passes when the assigned SID set exactly matches the expected principals' {
        InModuleScope woscap {
            Mock Get-UserRight { @('*S-1-5-32-544') }   # Administrators, secedit's leading-* form
            $d = @{ Type='UserRight'; Privilege='SeBackupPrivilege'; Operator='setequals'; Expected=@('Administrators') }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'UserRight fails (Open) when an extra principal holds the right' {
        InModuleScope woscap {
            Mock Get-UserRight { @('*S-1-5-32-544','*S-1-5-32-545') }  # Administrators + Users
            $d = @{ Type='UserRight'; Privilege='SeBackupPrivilege'; Operator='setequals'; Expected=@('Administrators') }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail'
        }
    }
    It 'UserRight passes when the right is assigned to no one and expected is empty' {
        InModuleScope woscap {
            Mock Get-UserRight { @() }
            $d = @{ Type='UserRight'; Privilege='SeTcbPrivilege'; Operator='setequals'; Expected=@() }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'UserRight returns Error (fail closed) when an expected principal cannot be resolved' {
        InModuleScope woscap {
            Mock Get-UserRight { @('*S-1-5-32-544') }
            $d = @{ Type='UserRight'; Privilege='SeBackupPrivilege'; Operator='setequals'; Expected=@('NoSuchPrincipalXyZ123') }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Error'
        }
    }
    It 'UserRight surfaces a clear message when the security policy cannot be read' {
        InModuleScope woscap {
            Mock Invoke-SecEditExport { throw 'secedit export produced no output (administrator privileges may be required to read the security policy).' }
            $d = @{ Type='UserRight'; Privilege='SeBackupPrivilege'; Operator='setequals'; Expected=@('Administrators') }
            $r = Test-Descriptor -Descriptor $d
            $r.Result   | Should -Be 'Error'
            $r.Observed | Should -BeLike '*administrator privileges may be required*'
        }
    }
    It 'passes an absent registry value when AbsentIsPass is set' {
        InModuleScope woscap {
            Mock Get-RegValue { $null }
            $d = @{ Type='Registry'; Path='HKLM:\X'; Name='SafeForScripting'; Operator='ne'; Expected=1; AbsentIsPass=$true }
            $r = Test-Descriptor -Descriptor $d
            $r.Result   | Should -Be 'Pass'
            $r.Observed | Should -Be '<absent>'
        }
    }
    It 'still evaluates a present value normally when AbsentIsPass is set' {
        InModuleScope woscap {
            Mock Get-RegValue { 1 }
            $d = @{ Type='Registry'; Path='HKLM:\X'; Name='SafeForScripting'; Operator='ne'; Expected=1; AbsentIsPass=$true }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail'
        }
    }
    It 'fails an absent registry value when AbsentIsPass is not set' {
        InModuleScope woscap {
            Mock Get-RegValue { $null }
            $d = @{ Type='Registry'; Path='HKLM:\X'; Name='Missing'; Operator='eq'; Expected=1 }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail'
        }
    }
    It 'returns NA with a reason when applicability is not met' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { $false } -ParameterFilter { $Fact -eq 'DomainJoined' }
            Mock Get-RegValue { throw 'must not be read' }
            $d = @{ Applicability=@{ DomainJoined=$true }; Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
            $r = Test-Descriptor -Descriptor $d
            $r.Result   | Should -Be 'NA'
            $r.Observed | Should -Match 'not domain-joined'
        }
    }
    It 'evaluates normally when applicability is met' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { $true } -ParameterFilter { $Fact -eq 'DomainJoined' }
            Mock Get-RegValue { 1 }
            $d = @{ Applicability=@{ DomainJoined=$true }; Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'returns Error (not NA) when an applicability predicate is unknown' {
        InModuleScope woscap {
            $d = @{ Applicability=@{ Bogus=$true }; Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Error'
        }
    }
    It 'evaluates a Cim descriptor' {
        InModuleScope woscap {
            Mock Get-CimSetting { 2 }
            $d = @{ Type='Cim'; ClassName='Win32_DeviceGuard'; Property='VirtualizationBasedSecurityStatus'; Operator='eq'; Expected=2 }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'evaluates a Cim descriptor against a collection with includes' {
        InModuleScope woscap {
            Mock Get-CimSetting { @(1,2) }
            $d = @{ Type='Cim'; ClassName='Win32_DeviceGuard'; Property='SecurityServicesRunning'; Operator='includes'; Expected=2 }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'fails a Cim descriptor when the class is unreadable' {
        InModuleScope woscap {
            Mock Get-CimSetting { $null }
            $d = @{ Type='Cim'; ClassName='Win32_Tpm'; Property='IsEnabled_InitialValue'; Operator='eq'; Expected=$true }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail'
        }
    }
    It 'evaluates a Certificate descriptor as a match count' {
        InModuleScope woscap {
            Mock Get-CertificateSetting { 'CN=DoD Root CA 3'; 'CN=DoD Root CA 5' }
            $d = @{ Type='Certificate'; Store='root'; Match=@{ Subject='DoD Root CA' }; Operator='ge'; Expected=1 }
            $r = Test-Descriptor -Descriptor $d
            $r.Result   | Should -Be 'Pass'
            $r.Observed | Should -Be 2
        }
    }
    It 'fails a Certificate descriptor when nothing matches' {
        InModuleScope woscap {
            Mock Get-CertificateSetting { }
            $d = @{ Type='Certificate'; Store='root'; Match=@{ Subject='ECA Root CA' }; Operator='ge'; Expected=1 }
            $r = Test-Descriptor -Descriptor $d
            $r.Result   | Should -Be 'Fail'
            $r.Observed | Should -Be 0
        }
    }
    It 'passes an Acl descriptor when every path is compliant' {
        InModuleScope woscap {
            Mock Test-AclCompliance { [pscustomobject]@{ Compliant=$true; Offenders='' } }
            $d = @{ Type='Acl'; Path=@('C:\a.evtx','C:\b.evtx'); AllowedPrincipals=@('NT AUTHORITY\SYSTEM') }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'fails an Acl descriptor and names the path at fault' {
        InModuleScope woscap {
            Mock Test-AclCompliance { [pscustomobject]@{ Compliant=$false; Offenders='BUILTIN\Users=FullControl' } }
            $d = @{ Type='Acl'; Path=@('C:\a.evtx'); AllowedPrincipals=@('NT AUTHORITY\SYSTEM') }
            $r = Test-Descriptor -Descriptor $d
            $r.Result   | Should -Be 'Fail'
            $r.Observed | Should -Match 'BUILTIN\\Users'
        }
    }
    It 'checks every path in a multi-path Acl descriptor' {
        InModuleScope woscap {
            Mock Test-AclCompliance { [pscustomobject]@{ Compliant=$true; Offenders='' } }
            $d = @{ Type='Acl'; Path=@('C:\','C:\Program Files','C:\Windows'); AllowedPrincipals=@('X') }
            $null = Test-Descriptor -Descriptor $d
            Should -Invoke Test-AclCompliance -Times 3 -Exactly
        }
    }
    It 'evaluates an OptionalFeature descriptor' {
        InModuleScope woscap {
            Mock Get-OptionalFeatureState { 'Enabled' }
            $d = @{ Type='OptionalFeature'; FeatureName='SMB1Protocol'; Operator='notin'; Expected=@('Enabled') }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail'
        }
    }
    It 'passes an OptionalFeature descriptor when the feature is disabled' {
        InModuleScope woscap {
            Mock Get-OptionalFeatureState { 'Disabled' }
            $d = @{ Type='OptionalFeature'; FeatureName='SMB1Protocol'; Operator='notin'; Expected=@('Enabled') }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'evaluates a Path descriptor for a binary that must not exist' {
        InModuleScope woscap {
            Mock Test-PathPresence { $false }
            $d = @{ Type='Path'; Path='%SystemRoot%\System32\telnet.exe'; Operator='eq'; Expected=$false }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'fails a Path descriptor when the forbidden binary is present' {
        InModuleScope woscap {
            Mock Test-PathPresence { $true }
            $d = @{ Type='Path'; Path='%SystemRoot%\System32\tftp.exe'; Operator='eq'; Expected=$false }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail'
        }
    }
    It 'passes a LocalAccount descriptor when no account is stale' {
        InModuleScope woscap {
            Mock Get-LocalAccountSetting { }
            $d = @{ Type='LocalAccount'; Scope='User'; Property='StaleNames'; ThresholdDays=35; Operator='setequals'; Expected=@() }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'fails a LocalAccount descriptor and names the offending account' {
        InModuleScope woscap {
            Mock Get-LocalAccountSetting { 'svc' }
            $d = @{ Type='LocalAccount'; Scope='User'; Property='NonExpiringNames'; Operator='setequals'; Expected=@() }
            $r = Test-Descriptor -Descriptor $d
            $r.Result   | Should -Be 'Fail'
            $r.Observed | Should -Be 'svc'
        }
    }
    It 'evaluates a LocalAccount password age against a threshold' {
        InModuleScope woscap {
            Mock Get-LocalAccountSetting { 75 }
            $d = @{ Type='LocalAccount'; Scope='User'; Name='Administrator'; Property='PasswordAgeDays'; Operator='le'; Expected=60 }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail'
        }
    }
    It 'returns NotReviewed with the question for a Manual descriptor' {
        InModuleScope woscap {
            $d = @{ Type='Manual'; Question='Is the camera physically covered when not in use?' }
            $r = Test-Descriptor -Descriptor $d
            $r.Result   | Should -Be 'NotReviewed'
            $r.Expected | Should -Be 'Is the camera physically covered when not in use?'
        }
    }
    It 'attaches evidence gathered from a child descriptor' {
        InModuleScope woscap {
            Mock Get-LocalAccountSetting { 'admin'; 'svc' }
            $d = @{
                Type     = 'Manual'
                Question = 'Are all members of the local Administrators group authorized?'
                Evidence = @{ Type='LocalAccount'; Scope='Group'; Name='Administrators'; Property='Members' }
            }
            $r = Test-Descriptor -Descriptor $d
            $r.Result   | Should -Be 'NotReviewed'
            $r.Observed | Should -Match 'admin'
            $r.Observed | Should -Match 'svc'
        }
    }
    It 'stays NotReviewed when evidence gathering fails' {
        InModuleScope woscap {
            Mock Get-LocalAccountSetting { throw 'denied' }
            $d = @{
                Type     = 'Manual'
                Question = 'Q?'
                Evidence = @{ Type='LocalAccount'; Scope='Group'; Name='X'; Property='Members' }
            }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'NotReviewed'
        }
    }
    It 'reports no evidence when none is declared' {
        InModuleScope woscap {
            $r = Test-Descriptor -Descriptor @{ Type='Manual'; Question='Q?' }
            $r.Observed | Should -Be '<no automated evidence>'
        }
    }
    It 'returns Error, not NotReviewed, when a descriptor declares no Operator' {
        InModuleScope woscap {
            # A dropped or misspelled Operator is a pack defect. Reporting it as
            # NotReviewed made it indistinguishable from "no check authored" and
            # excluded the rule from the Open count and compliance percentage.
            Mock Get-RegValue { 0 }
            $r = Test-Descriptor -Descriptor @{ Type='Registry'; Path='HKLM:\X'; Name='NoLMHash'; Expected=1 }
            $r.Result   | Should -Be 'Error'
            $r.Observed | Should -Match 'no Operator'
        }
    }
    It 'gathers without judging only when GatherOnly is explicitly set' {
        InModuleScope woscap {
            Mock Get-RegValue { 7 }
            $r = Test-Descriptor -Descriptor @{ Type='Registry'; Path='HKLM:\X'; Name='Y' } -GatherOnly
            $r.Result   | Should -Be 'NotReviewed'
            $r.Observed | Should -Be 7
        }
    }
}

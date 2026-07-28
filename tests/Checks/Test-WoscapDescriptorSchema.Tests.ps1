BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Test-WoscapDescriptorSchema' {
    It 'accepts a well-formed Registry descriptor' {
        InModuleScope woscap {
            $e = Test-WoscapDescriptorSchema -Descriptor @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
            @($e).Count | Should -Be 0
        }
    }
    It 'rejects an unknown Type' {
        InModuleScope woscap {
            @(Test-WoscapDescriptorSchema -Descriptor @{ Type='Bogus' }) | Should -Match 'unknown Type'
        }
    }
    It 'rejects a descriptor with no Type' {
        InModuleScope woscap {
            @(Test-WoscapDescriptorSchema -Descriptor @{ Operator='eq' }) | Should -Match 'missing Type'
        }
    }
    It 'rejects a Registry descriptor missing Name' {
        InModuleScope woscap {
            @(Test-WoscapDescriptorSchema -Descriptor @{ Type='Registry'; Path='HKLM:\X'; Operator='eq'; Expected=1 }) | Should -Match 'Name'
        }
    }
    It 'rejects an unknown Operator' {
        InModuleScope woscap {
            @(Test-WoscapDescriptorSchema -Descriptor @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='bogus'; Expected=1 }) | Should -Match 'unknown Operator'
        }
    }
    It 'rejects an unknown applicability predicate' {
        InModuleScope woscap {
            $d = @{ Applicability=@{ Nonsense=$true }; Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
            @(Test-WoscapDescriptorSchema -Descriptor $d) | Should -Match 'applicability predicate'
        }
    }
    It 'accepts every documented applicability predicate' {
        InModuleScope woscap {
            $d = @{
                Applicability = @{ DomainJoined=$true; TpmPresent=$true; CameraPresent=$true
                                   BluetoothPresent=$true; HypervisorPresent=$true
                                   OsBuildAtLeast=22000; OsBuildBelow=26100
                                   RegistryValueEquals=@{ Path='HKLM:\X'; Name='V'; Value=1 } }
                Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1
            }
            @(Test-WoscapDescriptorSchema -Descriptor $d).Count | Should -Be 0
        }
    }
    It 'validates composite children recursively' {
        InModuleScope woscap {
            $d = @{ Type='All'; Checks=@(
                @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
                @{ Type='Registry'; Path='HKLM:\X'; Operator='eq'; Expected=1 }
            )}
            @(Test-WoscapDescriptorSchema -Descriptor $d) | Should -Match 'Name'
        }
    }
    It 'names the failing child in the message' {
        InModuleScope woscap {
            $d = @{ Type='All'; Checks=@(
                @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
                @{ Type='Registry'; Path='HKLM:\X'; Operator='eq'; Expected=1 }
            )}
            @(Test-WoscapDescriptorSchema -Descriptor $d) | Should -Match 'Checks\[1\]'
        }
    }
    It 'rejects a composite with no children' {
        InModuleScope woscap {
            @(Test-WoscapDescriptorSchema -Descriptor @{ Type='Any'; Checks=@() }) | Should -Match 'Checks'
        }
    }
    It 'accepts a Manual descriptor with a Question' {
        InModuleScope woscap {
            @(Test-WoscapDescriptorSchema -Descriptor @{ Type='Manual'; Question='Q?' }).Count | Should -Be 0
        }
    }
    It 'rejects a Manual descriptor with no Question' {
        InModuleScope woscap {
            @(Test-WoscapDescriptorSchema -Descriptor @{ Type='Manual' }) | Should -Match 'Question'
        }
    }
    It 'does not require Operator on types that do not compare' {
        InModuleScope woscap {
            @(Test-WoscapDescriptorSchema -Descriptor @{ Type='Acl'; Path=@('C:\x'); AllowedPrincipals=@('SYSTEM') }).Count | Should -Be 0
        }
    }
    It 'does not require Operator inside a Manual Evidence subtree' {
        InModuleScope woscap {
            $d = @{
                Type='Manual'; Question='Q?'
                Evidence=@{ Type='LocalAccount'; Scope='Group'; Name='Administrators'; Property='Members' }
            }
            @(Test-WoscapDescriptorSchema -Descriptor $d).Count | Should -Be 0
        }
    }
    It 'still validates required keys inside a Manual Evidence subtree' {
        InModuleScope woscap {
            $d = @{ Type='Manual'; Question='Q?'; Evidence=@{ Type='LocalAccount'; Scope='Group' } }
            @(Test-WoscapDescriptorSchema -Descriptor $d) | Should -Match 'Property'
        }
    }
    It 'accepts every new descriptor type' {
        InModuleScope woscap {
            $samples = @(
                @{ Type='Cim'; ClassName='Win32_DeviceGuard'; Property='X'; Operator='eq'; Expected=1 }
                @{ Type='Certificate'; Store='root'; Match=@{ Subject='X' }; Operator='ge'; Expected=1 }
                @{ Type='OptionalFeature'; FeatureName='SMB1Protocol'; Operator='notin'; Expected=@('Enabled') }
                @{ Type='Path'; Path='C:\x.exe'; Operator='eq'; Expected=$false }
                @{ Type='LocalAccount'; Scope='User'; Property='StaleNames'; Operator='setequals'; Expected=@() }
            )
            foreach ($s in $samples) {
                @(Test-WoscapDescriptorSchema -Descriptor $s).Count | Should -Be 0 -Because "$($s.Type) must validate"
            }
        }
    }
}

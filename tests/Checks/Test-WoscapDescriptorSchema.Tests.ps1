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
                                   RegistryValueEquals=@{ Path='HKLM:\X'; Name='V'; Value=1 }
                                   RegistryValueIn=@{ Path='HKLM:\X'; Name='V'; Values=@(1, 2) } }
                Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1
            }
            @(Test-WoscapDescriptorSchema -Descriptor $d).Count | Should -Be 0
        }
    }
    It 'accepts a boolean Remediate opt-out and rejects a non-boolean one' {
        InModuleScope woscap {
            $ok = @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1; Remediate=$false; RemediateReason='why' }
            @(Test-WoscapDescriptorSchema -Descriptor $ok).Count | Should -Be 0
            $bad = @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1; Remediate='no' }
            @(Test-WoscapDescriptorSchema -Descriptor $bad) | Should -Match 'Remediate'
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

Describe 'Test-WoscapDescriptorSchema registry kind rules (#29)' {
    It 'rejects a Registry descriptor whose required kind cannot be resolved, naming the rule' {
        InModuleScope woscap {
            $d = @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='ge'; Expected='5' }
            @(Test-WoscapDescriptorSchema -Descriptor $d -Context 'R1') | Should -Match "R1.*ge"
        }
    }
    It 'rejects an unknown declared Kind' {
        InModuleScope woscap {
            $d = @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1; Kind='binary' }
            @(Test-WoscapDescriptorSchema -Descriptor $d) | Should -Match 'binary'
        }
    }
    It 'accepts NameCase Exact on a Registry descriptor' {
        InModuleScope woscap {
            $d = @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1; NameCase='Exact' }
            @(Test-WoscapDescriptorSchema -Descriptor $d).Count | Should -Be 0
        }
    }
    It 'rejects a NameCase other than Exact' {
        InModuleScope woscap {
            $d = @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1; NameCase='Insensitive' }
            @(Test-WoscapDescriptorSchema -Descriptor $d) | Should -Match 'NameCase'
        }
    }
    It 'rejects NameCase on a non-Registry descriptor' {
        InModuleScope woscap {
            $d = @{ Type='Service'; Name='X'; Operator='eq'; Expected='Auto'; NameCase='Exact' }
            @(Test-WoscapDescriptorSchema -Descriptor $d) | Should -Match 'NameCase'
        }
    }
    It 'checks the kind of composite children' {
        InModuleScope woscap {
            $d = @{ Type='All'; Checks=@(
                @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
                @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='regex'; Expected=5 }
            )}
            @(Test-WoscapDescriptorSchema -Descriptor $d -Context 'C1') | Should -Match 'C1\.Checks\[1\].*regex'
        }
    }
    It 'checks the kind of Evidence children that declare an Operator' {
        InModuleScope woscap {
            $d = @{ Type='Manual'; Question='Q?'
                    Evidence=@{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='setequals'; Expected=@(1); Kind='dword' } }
            @(Test-WoscapDescriptorSchema -Descriptor $d -Context 'M1') | Should -Match 'M1\.Evidence'
        }
    }
    It 'accepts operator-less Registry Evidence, which is reported and not judged' {
        InModuleScope woscap {
            $d = @{ Type='Manual'; Question='Q?'; Evidence=@{ Type='Registry'; Path='HKLM:\X'; Name='Y' } }
            @(Test-WoscapDescriptorSchema -Descriptor $d).Count | Should -Be 0
        }
    }
    It 'NameCase is validated inside composite and Evidence children' {
        InModuleScope woscap {
            $d = @{ Type='Manual'; Question='Q?'
                    Evidence=@{ Type='Any'; Checks=@(@{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='exists'; Expected=$true; NameCase='exact ' }) } }
            @(Test-WoscapDescriptorSchema -Descriptor $d) | Should -Match 'NameCase'
        }
    }
}

Describe 'Shipped content packs pass the descriptor schema' {
    It 'every Content/*/checks.psd1 descriptor validates with 0 problems' {
        InModuleScope woscap {
            $problems = foreach ($dir in Get-ChildItem -LiteralPath (Join-Path $script:WoscapModuleRoot 'Content') -Directory) {
                if (-not (Test-Path -LiteralPath (Join-Path $dir.FullName 'checks.psd1'))) { continue }
                $data = Import-ContentPack -Path $dir.FullName -WarningAction SilentlyContinue
                foreach ($key in @($data.Keys)) {
                    if ($data[$key] -is [hashtable]) {
                        Test-WoscapDescriptorSchema -Descriptor $data[$key] -Context "$($dir.Name)/$key"
                    }
                }
            }
            @($problems) | Should -BeNullOrEmpty
        }
    }
}

Describe 'Test-WoscapDescriptorSchema registry gate value types (#29)' {
    It 'rejects a RegistryValueIn gate mixing integer and string values' {
        InModuleScope woscap {
            $d = @{ Applicability=@{ RegistryValueIn=@{ Path='HKLM:\X'; Name='V'; Values=@(1, '2') } }
                    Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
            @(Test-WoscapDescriptorSchema -Descriptor $d) | Should -Match 'RegistryValueIn'
        }
    }
    It 'rejects a RegistryValueEquals gate whose value is neither an integer nor a string' {
        InModuleScope woscap {
            $d = @{ Applicability=@{ RegistryValueEquals=@{ Path='HKLM:\X'; Name='V'; Value=$true } }
                    Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
            @(Test-WoscapDescriptorSchema -Descriptor $d) | Should -Match 'RegistryValueEquals'
        }
    }
    It 'accepts all-integer and all-string gate values' {
        InModuleScope woscap {
            foreach ($a in @(
                @{ RegistryValueIn=@{ Path='HKLM:\X'; Name='V'; Values=@(1, 2) } }
                @{ RegistryValueIn=@{ Path='HKLM:\X'; Name='V'; Values=@('2', '3') } }
                @{ RegistryValueEquals=@{ Path='HKLM:\X'; Name='V'; Value='x' } }
            )) {
                $d = @{ Applicability=$a; Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
                @(Test-WoscapDescriptorSchema -Descriptor $d).Count | Should -Be 0
            }
        }
    }
}

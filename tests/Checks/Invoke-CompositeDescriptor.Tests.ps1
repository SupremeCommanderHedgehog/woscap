BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Composite descriptors' {
    It 'All passes only when every child passes' {
        InModuleScope woscap {
            $d = @{ Type='All'; Checks=@(
                @{ Type='ScriptBlock'; Script={ 'Pass' } }
                @{ Type='ScriptBlock'; Script={ 'Pass' } }
            )}
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'All fails when any child fails' {
        InModuleScope woscap {
            $d = @{ Type='All'; Checks=@(
                @{ Type='ScriptBlock'; Script={ 'Pass' } }
                @{ Type='ScriptBlock'; Script={ 'Fail' } }
            )}
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail'
        }
    }
    It 'Any passes when at least one child passes' {
        InModuleScope woscap {
            $d = @{ Type='Any'; Checks=@(
                @{ Type='ScriptBlock'; Script={ 'Fail' } }
                @{ Type='ScriptBlock'; Script={ 'Pass' } }
            )}
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'Any fails when every child fails' {
        InModuleScope woscap {
            $d = @{ Type='Any'; Checks=@(
                @{ Type='ScriptBlock'; Script={ 'Fail' } }
                @{ Type='ScriptBlock'; Script={ 'Fail' } }
            )}
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail'
        }
    }
    It 'All ignores an NA child' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { $false } -ParameterFilter { $Fact -eq 'DomainJoined' }
            $d = @{ Type='All'; Checks=@(
                @{ Type='ScriptBlock'; Script={ 'Pass' } }
                @{ Applicability=@{ DomainJoined=$true }; Type='ScriptBlock'; Script={ 'Fail' } }
            )}
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'Any ignores an NA child' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { $false } -ParameterFilter { $Fact -eq 'DomainJoined' }
            $d = @{ Type='Any'; Checks=@(
                @{ Type='ScriptBlock'; Script={ 'Fail' } }
                @{ Applicability=@{ DomainJoined=$true }; Type='ScriptBlock'; Script={ 'Pass' } }
            )}
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail'
        }
    }
    It 'is NA when every child is NA' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { $false } -ParameterFilter { $Fact -eq 'DomainJoined' }
            $d = @{ Type='All'; Checks=@(
                @{ Applicability=@{ DomainJoined=$true }; Type='ScriptBlock'; Script={ 'Pass' } }
                @{ Applicability=@{ DomainJoined=$true }; Type='ScriptBlock'; Script={ 'Fail' } }
            )}
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'NA'
        }
    }
    It 'propagates Error from a child rather than reporting a pass' {
        InModuleScope woscap {
            $d = @{ Type='Any'; Checks=@(
                @{ Type='ScriptBlock'; Script={ 'Pass' } }
                @{ Type='ScriptBlock'; Script={ throw 'boom' } }
            )}
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Error'
        }
    }
    It 'returns Error for a composite with no children' {
        InModuleScope woscap {
            (Test-Descriptor -Descriptor @{ Type='All'; Checks=@() }).Result | Should -Be 'Error'
        }
    }
    It 'explains an empty composite rather than leaking an exception message' {
        InModuleScope woscap {
            # Pins the message, not just the result: an unguarded $null.Count
            # also yields Error, but with an opaque StrictMode message.
            $r = Test-Descriptor -Descriptor @{ Type='All'; Checks=@() }
            $r.Observed | Should -Match 'has no Checks'
        }
    }
    It 'returns Error for a composite with no Checks key at all' {
        InModuleScope woscap {
            $r = Test-Descriptor -Descriptor @{ Type='Any' }
            $r.Result   | Should -Be 'Error'
            $r.Observed | Should -Match 'has no Checks'
        }
    }
    It 'nests composites' {
        InModuleScope woscap {
            $d = @{ Type='All'; Checks=@(
                @{ Type='ScriptBlock'; Script={ 'Pass' } }
                @{ Type='Any'; Checks=@(
                    @{ Type='ScriptBlock'; Script={ 'Fail' } }
                    @{ Type='ScriptBlock'; Script={ 'Pass' } }
                )}
            )}
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'All ignores a NotReviewed child instead of counting it as non-passing' {
        InModuleScope woscap {
            # An All containing a Manual child previously always reported Fail,
            # flagging a compliant machine and burying the manual question.
            $d = @{ Type='All'; Checks=@(
                @{ Type='ScriptBlock'; Script={ 'Pass' } }
                @{ Type='Manual'; Question='Is the site policy documented?' }
            )}
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'Any ignores a NotReviewed child' {
        InModuleScope woscap {
            $d = @{ Type='Any'; Checks=@(
                @{ Type='ScriptBlock'; Script={ 'Fail' } }
                @{ Type='Manual'; Question='Q?' }
            )}
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail'
        }
    }
    It 'is NotReviewed when every child is NotReviewed' {
        InModuleScope woscap {
            $d = @{ Type='All'; Checks=@(
                @{ Type='Manual'; Question='Q1?' }
                @{ Type='Manual'; Question='Q2?' }
            )}
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'NotReviewed'
        }
    }
    It 'is NotReviewed when children are a mix of NA and NotReviewed' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { $false } -ParameterFilter { $Fact -eq 'DomainJoined' }
            $d = @{ Type='All'; Checks=@(
                @{ Applicability=@{ DomainJoined=$true }; Type='ScriptBlock'; Script={ 'Pass' } }
                @{ Type='Manual'; Question='Q?' }
            )}
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'NotReviewed'
        }
    }
    It 'reports every child reading in Observed' {
        InModuleScope woscap {
            Mock Get-RegValue { 7 }
            $d = @{ Type='All'; Checks=@(
                @{ Type='Registry'; Path='HKLM:\X'; Name='A'; Operator='eq'; Expected=1 }
                @{ Type='Registry'; Path='HKLM:\X'; Name='B'; Operator='eq'; Expected=1 }
            )}
            (Test-Descriptor -Descriptor $d).Observed | Should -Be '7; 7'
        }
    }
    It 'expresses a range excluding zero as an All of ne and le' {
        InModuleScope woscap {
            Mock Get-RegValue { 0 }
            $d = @{ Type='All'; Checks=@(
                @{ Type='Registry'; Path='HKLM:\X'; Name='MaximumPasswordAge'; Operator='ne'; Expected=0 }
                @{ Type='Registry'; Path='HKLM:\X'; Name='MaximumPasswordAge'; Operator='le'; Expected=60 }
            )}
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail'
        }
    }
}

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
}

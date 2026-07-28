BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

# The invariant this file exists to defend:
#
#   A read that FAILED must never produce Result='Pass'.
#
# The first version of this file was table-driven but still example-based: ONE
# hand-picked operator per type, plus a $noRead exemption list asserted without
# proof. Both holes hid real bugs - Certificate was only exercised with 'eq 0',
# the single direction where a swallowed sentinel happens to Fail, so the count
# of 1 that passed every 'ge 1' rule went unnoticed.
#
# So this is now a genuine cross-product: every reading type is crossed with
# EVERY operator direction that could score a degenerate reading as compliant,
# and no type is exempt by declaration.

BeforeDiscovery {
    # Operator directions that a degenerate reading (null, empty, zero, a
    # placeholder string, or a miscounted sentinel) could satisfy.
    $script:DegeneratePassingOperators = @(
        @{ Operator = 'eq';        Expected = 0 }
        @{ Operator = 'ne';        Expected = 1 }
        @{ Operator = 'ge';        Expected = 1 }
        @{ Operator = 'le';        Expected = 60 }
        @{ Operator = 'notin';     Expected = @('Enabled') }
        @{ Operator = 'setequals'; Expected = @() }
        @{ Operator = 'subsetof';  Expected = @('Administrator') }
        @{ Operator = 'exists';    Expected = $false }
    )

    # Every descriptor Type that performs a read, with the call to break and a
    # descriptor skeleton. Nothing is exempted: SecEdit/UserRight shell out to
    # secedit.exe, AuditPolicy to auditpol.exe, Service reads Win32_Service -
    # the previous $noRead list claimed all four "perform no read of their own",
    # which was simply false.
    $script:ReadingTypes = @(
        @{ Type='Registry';        Breaks='Get-ItemProperty';           Base=@{ Type='Registry'; Path='HKLM:\X'; Name='Y'; AbsentIsPass=$true } }
        @{ Type='SecEdit';         Breaks='Invoke-SecEditExportRaw';    Base=@{ Type='SecEdit'; Name='MinimumPasswordLength' } }
        @{ Type='UserRight';       Breaks='Invoke-SecEditExportRaw';    Base=@{ Type='UserRight'; Privilege='SeBackupPrivilege' } }
        @{ Type='AuditPolicy';     Breaks='Invoke-AuditPolRaw';         Base=@{ Type='AuditPolicy'; Subcategory='Logon' } }
        @{ Type='Service';         Breaks='Get-CimInstance';            Base=@{ Type='Service'; Name='seclogon' } }
        @{ Type='Cim';             Breaks='Get-CimInstance';            Base=@{ Type='Cim'; ClassName='Win32_DeviceGuard'; Property='P' } }
        @{ Type='Certificate';     Breaks='Get-ChildItem';              Base=@{ Type='Certificate'; Store='root'; Match=@{ Subject='X' } } }
        @{ Type='OptionalFeature'; Breaks='Get-CimInstance';            Base=@{ Type='OptionalFeature'; FeatureName='SMB1Protocol' } }
        @{ Type='Path';            Breaks='Test-Path';                  Base=@{ Type='Path'; Path='C:\x.exe' } }
        @{ Type='LocalAccount';    Breaks='Get-WoscapAdsiObject';       Base=@{ Type='LocalAccount'; Scope='Group'; Name='Administrators'; Property='Members' } }
    )

    # The cross-product itself.
    $script:FailClosedCases = foreach ($t in $script:ReadingTypes) {
        foreach ($op in $script:DegeneratePassingOperators) {
            @{
                TypeName = $t.Type
                Breaks   = $t.Breaks
                Operator = $op.Operator
                Expected = $op.Expected
                Base     = $t.Base
            }
        }
    }
}

Describe 'Fail-closed invariant (cross-product over every reading type)' {

    It '<TypeName> with <Operator> does not Pass when the read fails' -ForEach $script:FailClosedCases {
        InModuleScope woscap -Parameters @{ Breaks=$Breaks; Operator=$Operator; Expected=$Expected; Base=$Base } {
            Clear-WoscapReadCache
            $descriptor = $Base.Clone()
            $descriptor['Operator'] = $Operator
            $descriptor['Expected'] = $Expected

            Mock -CommandName $Breaks -MockWith { throw 'simulated read failure (access denied)' }

            $r = Test-Descriptor -Descriptor $descriptor
            $r.Result | Should -Not -Be 'Pass' -Because "a failed $Breaks read must never score as compliant"
            $r.Result | Should -Not -Be 'NA'   -Because 'NA removes the rule from scoring, which hides it as effectively as a Pass'
        }
    }

    It 'the Acl type does not Pass when the path cannot be read' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            Mock Get-Acl { throw 'access denied' }
            $r = Test-Descriptor -Descriptor @{ Type='Acl'; Path=@('C:\x.evtx'); AllowedPrincipals=@('NT AUTHORITY\SYSTEM') }
            $r.Result | Should -Be 'Fail'
        }
    }
}

Describe 'Fail-closed invariant: applicability gates' {
    It 'a failed presence read yields Error, never NA' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            Mock Get-CimInstance { throw 'access denied' }
            $d = @{ Applicability=@{ TpmPresent=$true }; Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Error'
        }
    }
    It 'a failed OsBuild read yields Error, never NA' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            Mock Get-CimInstance { throw 'access denied' }
            $d = @{ Applicability=@{ OsBuildAtLeast=22000 }; Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Error'
        }
    }
    It 'a failed RegistryValueEquals read yields Error, never NA' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            Mock Get-ItemProperty { throw [System.Security.SecurityException]::new('access denied') }
            $d = @{ Applicability=@{ RegistryValueEquals=@{ Path='HKLM:\X'; Name='V'; Value=1 } }
                    Type='Registry'; Path='HKLM:\Y'; Name='Z'; Operator='eq'; Expected=1 }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Error'
        }
    }
}

Describe 'Fail-closed invariant: empty is still real evidence' {
    # The other side of the invariant. Without these the fix could degenerate
    # into "everything is Error", which would be just as useless.
    It 'an empty-but-readable group still passes subsetof' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            Mock Get-WoscapLocalGroupMemberRaw { @() }
            $d = @{ Type='LocalAccount'; Scope='Group'; Name='Backup Operators'; Property='Members'; Operator='subsetof'; Expected=@('Administrator') }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'a genuinely absent registry value still passes AbsentIsPass' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            Mock Get-ItemProperty { throw [System.Management.Automation.ItemNotFoundException]::new('no key') }
            $d = @{ Type='Registry'; Path='HKLM:\X'; Name='SafeForScripting'; Operator='ne'; Expected=1; AbsentIsPass=$true }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'a readable certificate store with no match still passes eq 0' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            Mock Get-WoscapCertStore { ,@() }
            $d = @{ Type='Certificate'; Store='disallowed'; Match=@{ Thumbprint='ABC' }; Operator='eq'; Expected=0 }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
}

Describe 'Fail-closed invariant: coverage' {
    It 'crosses every reading descriptor type with every degenerate operator' -ForEach @(
        @{ Covered = @($script:ReadingTypes | ForEach-Object { $_.Type }) }
    ) {
        $known = InModuleScope woscap {
            # Read the type list out of the schema validator itself rather than
            # restating it. A Type added there but not covered here then fails
            # this test, instead of silently escaping the invariant the way the
            # previous hand-maintained $noRead list let four types escape.
            $src = (Get-Command Test-WoscapDescriptorSchema).ScriptBlock.ToString()
            $block = [regex]::Match($src, '\$requiredKeys\s*=\s*@\{(?<body>[\s\S]*?)\n\s{4}\}')
            $block.Success | Should -BeTrue -Because 'the validator must expose a parseable requiredKeys table'
            [regex]::Matches($block.Groups['body'].Value, "(?m)^\s*'(?<name>[A-Za-z]+)'\s*=") |
                ForEach-Object { $_.Groups['name'].Value }
        }
        @($known).Count | Should -BeGreaterThan 10 -Because 'the type list should have parsed, not come back empty'

        # ScriptBlock runs caller-supplied code, Manual is answered by a human,
        # and All/Any only compose children that are themselves covered. Acl has
        # its own case above because its verdict is not produced through
        # Compare-WoscapValue, so the operator cross-product does not apply.
        $composesOrDefers = @('ScriptBlock','Manual','All','Any')
        $accountedFor = @($Covered) + $composesOrDefers + @('Acl')

        $missing = @($known | Where-Object { $accountedFor -notcontains $_ })
        $missing | Should -BeNullOrEmpty -Because 'every reading Type must appear in the cross-product'
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapRemediationPlan' {
    It 'maps a Registry descriptor with an int Expected to a dword action' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'R-1'; Title = 'Reg rule'; Status = 'Open' })
            $pack  = @{ 'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Test'; Name = 'Foo'; Operator = 'eq'; Expected = 1 } }
            $plan  = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            $plan.Count             | Should -Be 1
            $plan[0].Type           | Should -Be 'Registry'
            $plan[0].Automatable    | Should -BeTrue
            $plan[0].Registry.Path  | Should -Be 'HKLM:\SOFTWARE\Test'
            $plan[0].Registry.Name  | Should -Be 'Foo'
            $plan[0].Registry.Data  | Should -Be 1
            $plan[0].Registry.Kind  | Should -Be 'dword'
        }
    }
    It 'maps a Registry descriptor with a string Expected to a string action' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'R-2'; Title = 'Str rule'; Status = 'Open' })
            $pack  = @{ 'R-2' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = 'eq'; Expected = 'abc' } }
            (@(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack))[0].Registry.Kind | Should -Be 'string'
        }
    }
    It 'maps a [long] Expected that fits in Int32 to a dword action' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'R-3'; Title = 'Long dword'; Status = 'Open' })
            $pack  = @{ 'R-3' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = 'eq'; Expected = [long]32768 } }
            $plan  = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            $plan[0].Automatable   | Should -BeTrue
            $plan[0].Registry.Kind | Should -Be 'dword'
            $plan[0].Registry.Data | Should -Be 32768
        }
    }
    It 'makes an Expected outside Int32 Manual (REG_DWORD reads back as Int32, so eq never passes)' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'R-3'; Title = 'Big dword'; Status = 'Open' })
            $pack  = @{ 'R-3' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = 'eq'; Expected = [long]4294967295 } }
            $action = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0]
            $action.Type         | Should -Be 'Manual'
            $action.Automatable  | Should -BeFalse
            $action.CheckType    | Should -Be 'Registry'
            $action.ManualReason | Should -Match '4294967295'
        }
    }
    It 'keeps operator <Operator> with Expected <Expected> automatic' -ForEach @(
        @{ Operator = 'eq'; Expected = 0;     Kind = 'dword' }
        @{ Operator = 'eq'; Expected = 'abc'; Kind = 'string' }
        @{ Operator = 'ge'; Expected = 6;     Kind = 'dword' }
        @{ Operator = 'le'; Expected = 10;    Kind = 'dword' }
        @{ Operator = 'eq'; Expected = -1;    Kind = 'dword' }
        @{ Operator = 'le'; Expected = -5;    Kind = 'dword' }
    ) {
        InModuleScope woscap -Parameters @{ Operator = $Operator; Expected = $Expected; Kind = $Kind } {
            param($Operator, $Expected, $Kind)
            $rules = @([pscustomobject]@{ StigId = 'R-1'; Title = 'r'; Status = 'Open' })
            $pack  = @{ 'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = $Operator; Expected = $Expected } }
            $action = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0]
            $action.Type          | Should -Be 'Registry'
            $action.Automatable   | Should -BeTrue
            $action.Registry.Data | Should -Be $Expected
            $action.Registry.Kind | Should -Be $Kind
        }
    }
    It 'makes operator <Operator> Manual and names it in the reason' -ForEach @(
        @{ Operator = 'ne';         Expected = 0 }
        @{ Operator = 'regex';      Expected = '\S' }
        @{ Operator = 'in';         Expected = @(1, 2) }
        @{ Operator = 'notin';      Expected = @(0) }
        @{ Operator = 'sequence';   Expected = @('a', 'b') }
        @{ Operator = 'exists';     Expected = $true }
        @{ Operator = 'includes';   Expected = 'a' }
        @{ Operator = 'setequals';  Expected = @('a') }
        @{ Operator = 'subsetof';   Expected = @('a') }
        @{ Operator = 'supersetof'; Expected = @('a') }
        @{ Operator = 'bogus';      Expected = 1 }
    ) {
        InModuleScope woscap -Parameters @{ Operator = $Operator; Expected = $Expected } {
            param($Operator, $Expected)
            $rules = @([pscustomobject]@{ StigId = 'R-1'; Title = 'r'; Status = 'Open' })
            $pack  = @{ 'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = $Operator; Expected = $Expected } }
            $action = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0]
            $action.Type         | Should -Be 'Manual'
            $action.Automatable  | Should -BeFalse
            $action.Registry     | Should -BeNullOrEmpty
            $action.CheckType    | Should -Be 'Registry'
            $action.ManualReason | Should -Match ([regex]::Escape("operator '$Operator'"))
        }
    }
    It 'makes a Registry descriptor with no Operator Manual (it evaluates to Error, never Pass)' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'R-1'; Title = 'r'; Status = 'Open' })
            $pack  = @{ 'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Expected = 1 } }
            $action = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0]
            $action.Type         | Should -Be 'Manual'
            $action.ManualReason | Should -Match 'Operator'
        }
    }
    It 'honors a declared Kind (<Case>)' -ForEach @(
        @{ Case = 'REG_SZ number, le'; Operator = 'le'; Expected = 10;    Declared = 'string'; Data = '10' }
        @{ Case = 'REG_SZ number, eq'; Operator = 'eq'; Expected = 1;     Declared = 'string'; Data = '1' }
        @{ Case = 'REG_SZ text';       Operator = 'eq'; Expected = 'abc'; Declared = 'string'; Data = 'abc' }
        @{ Case = 'dword';             Operator = 'eq'; Expected = 1;     Declared = 'dword';  Data = 1 }
    ) {
        InModuleScope woscap -Parameters @{ Operator = $Operator; Expected = $Expected; Declared = $Declared; Data = $Data } {
            param($Operator, $Expected, $Declared, $Data)
            $rules = @([pscustomobject]@{ StigId = 'R-1'; Title = 'r'; Status = 'Open' })
            $pack  = @{ 'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = $Operator; Expected = $Expected; Kind = $Declared } }
            $action = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0]
            $action.Automatable   | Should -BeTrue
            $action.Registry.Kind | Should -Be $Declared
            $action.Registry.Data | Should -BeOfType $Data.GetType()
            $action.Registry.Data | Should -Be $Data
        }
    }
    It 'makes a declared Kind it cannot honor Manual (<Case>)' -ForEach @(
        @{ Case = 'dword with text';  Operator = 'eq'; Expected = 'abc'; Declared = 'dword' }
        @{ Case = 'unsupported Kind'; Operator = 'eq'; Expected = 1;     Declared = 'qword' }
        @{ Case = 'string threshold'; Operator = 'ge'; Expected = '6';   Declared = 'string' }
    ) {
        InModuleScope woscap -Parameters @{ Operator = $Operator; Expected = $Expected; Declared = $Declared } {
            param($Operator, $Expected, $Declared)
            $rules = @([pscustomobject]@{ StigId = 'R-1'; Title = 'r'; Status = 'Open' })
            $pack  = @{ 'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = $Operator; Expected = $Expected; Kind = $Declared } }
            $action = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0]
            $action.Type         | Should -Be 'Manual'
            $action.ManualReason | Should -Not -BeNullOrEmpty
        }
    }
    It 'never automates a rule under the current-user hive (<Path>)' -ForEach @(
        @{ Path = 'HKCU:\SOFTWARE\Policies\X' }
        @{ Path = 'hkcu:\Software\X' }
        @{ Path = 'Registry::HKEY_CURRENT_USER\Software\X' }
        @{ Path = 'Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\X' }
    ) {
        InModuleScope woscap -Parameters @{ Path = $Path } {
            param($Path)
            $rules = @([pscustomobject]@{ StigId = 'R-1'; Title = 'r'; Status = 'Open' })
            $pack  = @{ 'R-1' = @{ Type = 'Registry'; Path = $Path; Name = 'N'; Operator = 'eq'; Expected = 1 } }
            $action = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0]
            $action.Type         | Should -Be 'Manual'
            $action.Automatable  | Should -BeFalse
            $action.ManualReason | Should -Match 'HKCU'
        }
    }
    It 'makes <Operator> with a non-encodable Expected (<Case>) Manual' -ForEach @(
        @{ Case = 'string threshold'; Operator = 'ge'; Expected = '6' }
        @{ Case = 'array';            Operator = 'eq'; Expected = @(1, 2) }
        @{ Case = 'bool';             Operator = 'eq'; Expected = $true }
        @{ Case = 'double';           Operator = 'le'; Expected = 1.5 }
        @{ Case = 'above Int32';      Operator = 'ge'; Expected = [long]2147483648 }
    ) {
        InModuleScope woscap -Parameters @{ Operator = $Operator; Expected = $Expected } {
            param($Operator, $Expected)
            $rules = @([pscustomobject]@{ StigId = 'R-1'; Title = 'r'; Status = 'Open' })
            $pack  = @{ 'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = $Operator; Expected = $Expected } }
            $action = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0]
            $action.Type         | Should -Be 'Manual'
            $action.Automatable  | Should -BeFalse
            $action.ManualReason | Should -Not -BeNullOrEmpty
        }
    }
    It 'aggregates paired Success and Failure rules for one subcategory into a single action' {
        InModuleScope woscap {
            $rules = @(
                [pscustomobject]@{ StigId = 'A-1'; Title = 'Logon Success'; Status = 'Open' },
                [pscustomobject]@{ StigId = 'A-2'; Title = 'Logon Failure'; Status = 'Open' }
            )
            $pack = @{
                'A-1' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Operator = 'includes'; Expected = 'Success' }
                'A-2' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Operator = 'includes'; Expected = 'Failure' }
            }
            $plan = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            @($plan | Where-Object { $_.Type -eq 'AuditPolicy' }).Count | Should -Be 1
            $audit = @($plan | Where-Object { $_.Type -eq 'AuditPolicy' })[0]
            $audit.Audit.Subcategory | Should -Be 'Logon'
            @($audit.Audit.Directions | Sort-Object) | Should -Be @('failure','success')
        }
    }
    It 'keeps a Success-only subcategory to just the success direction' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'A-3'; Title = 'CredVal'; Status = 'Open' })
            $pack  = @{ 'A-3' = @{ Type = 'AuditPolicy'; Subcategory = 'Credential Validation'; Expected = 'Success' } }
            $audit = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0]
            $audit.Audit.Directions | Should -Be @('success')
        }
    }
    It 'makes an AuditPolicy rule Manual when Expected is not Success or Failure' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'A-8'; Title = 'Odd'; Status = 'Open' })
            $pack  = @{ 'A-8' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Expected = 'Bogus' } }
            $plan  = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            $plan.Count | Should -Be 1
            $plan[0].Type         | Should -Be 'Manual'
            $plan[0].CheckType    | Should -Be 'AuditPolicy'
            $plan[0].ManualReason | Should -Match "'Bogus'"
        }
    }
    It 'never emits an AuditPolicy action with empty Directions; valid siblings still merge' {
        InModuleScope woscap {
            $rules = @(
                [pscustomobject]@{ StigId = 'A-8'; Title = 'Odd'; Status = 'Open' },
                [pscustomobject]@{ StigId = 'A-9'; Title = 'Fail'; Status = 'Open' }
            )
            $pack = @{
                'A-8' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Expected = 'Bogus' }
                'A-9' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Expected = 'FAILURE' }
            }
            $plan  = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            $audit = @($plan | Where-Object { $_.Type -eq 'AuditPolicy' })
            $audit.Count | Should -Be 1
            $audit[0].Audit.Directions | Should -Be @('failure')
            @($audit[0].StigIds) | Should -Be @('A-9')
            @($plan | Where-Object { $_.Type -eq 'Manual' }).StigId | Should -Be 'A-8'
        }
    }
    It 'reports an unsupported CheckType as Manual with a reason' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'S-1'; Title = 'Svc rule'; Status = 'Open' })
            $pack  = @{ 'S-1' = @{ Type = 'Service'; Name = 'W32Time' } }
            $action = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0]
            $action.Type         | Should -Be 'Manual'
            $action.Automatable  | Should -BeFalse
            $action.CheckType    | Should -Be 'Service'
            $action.ManualReason | Should -Match "Service"
        }
    }
    It 'reports a missing descriptor as Manual' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'M-1'; Title = 'No pack'; Status = 'Open' })
            $action = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack @{})[0]
            $action.Type      | Should -Be 'Manual'
            $action.CheckType | Should -Be ''
        }
    }
    It 'reports an incomplete Registry descriptor as Manual (CheckType preserved)' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'R-9'; Title = 'Partial'; Status = 'Open' })
            $pack  = @{ 'R-9' = @{ Type = 'Registry'; Path = 'p'; Name = 'n' } }  # no Expected
            $action = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0]
            $action.Type      | Should -Be 'Manual'
            $action.CheckType | Should -Be 'Registry'
        }
    }
    It 'honours a Remediate = $false opt-out on an otherwise automatable Registry rule, naming why' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'R-7'; Title = 'Opted out'; Status = 'Open' })
            $pack  = @{ 'R-7' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = 'eq'; Expected = 1
                                   Remediate = $false; RemediateReason = 'NA on classified systems' } }
            $action = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0]
            $action.Automatable  | Should -BeFalse
            $action.Type         | Should -Be 'Manual'
            $action.CheckType    | Should -Be 'Registry'
            $action.ManualReason | Should -Match 'opts this rule out of automatic remediation'
            $action.ManualReason | Should -Match 'NA on classified systems'
        }
    }
    It 'keeps an opted-out AuditPolicy rule out of its subcategory merge' {
        InModuleScope woscap {
            $rules = @(
                [pscustomobject]@{ StigId = 'A-1'; Title = 's'; Status = 'Open' }
                [pscustomobject]@{ StigId = 'A-2'; Title = 'f'; Status = 'Open' }
            )
            $pack = @{
                'A-1' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Operator = 'includes'; Expected = 'Success' }
                'A-2' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Operator = 'includes'; Expected = 'Failure'; Remediate = $false }
            }
            $plan = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            $audit = @($plan | Where-Object Automatable)
            $audit.Count | Should -Be 1
            @($audit[0].Audit.Directions) | Should -Be @('success')
            @($audit[0].StigIds) | Should -Be @('A-1')
            ($plan | Where-Object StigId -eq 'A-2').Type | Should -Be 'Manual'
        }
    }
    It 'returns an empty array for no failed rules' {
        InModuleScope woscap {
            @(Get-WoscapRemediationPlan -FailedRule @() -ContentPack @{}).Count | Should -Be 0
        }
    }
    It 'gives a Registry action StigIds of just its own rule' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'R-1'; Title = 'r'; Status = 'Open' })
            $pack  = @{ 'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = 'eq'; Expected = 1 } }
            @((Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0].StigIds) | Should -Be @('R-1')
        }
    }
    It 'gives a merged AuditPolicy action StigIds of every rule in its subcategory, in input order' {
        InModuleScope woscap {
            $rules = @(
                [pscustomobject]@{ StigId = 'A-2'; Title = 'f'; Status = 'Open' }
                [pscustomobject]@{ StigId = 'X-1'; Title = 'x'; Status = 'Open' }
                [pscustomobject]@{ StigId = 'A-1'; Title = 's'; Status = 'Open' }
            )
            $pack = @{
                'A-1' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon';  Expected = 'Success' }
                'A-2' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon';  Expected = 'Failure' }
                'X-1' = @{ Type = 'AuditPolicy'; Subcategory = 'Logoff'; Expected = 'Success' }
            }
            $plan = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            $plan.Count | Should -Be 2
            $logon = $plan | Where-Object { $_.Audit.Subcategory -eq 'Logon' }
            @($logon.StigIds) | Should -Be @('A-2', 'A-1')
            @(($plan | Where-Object { $_.Audit.Subcategory -eq 'Logoff' }).StigIds) | Should -Be @('X-1')
        }
    }
    It 'gives a Manual action StigIds of just its own rule' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'M-1'; Title = 'm'; Status = 'Open' })
            @((Get-WoscapRemediationPlan -FailedRule $rules -ContentPack @{})[0].StigIds) | Should -Be @('M-1')
        }
    }
}

# #29: a fix may only write a kind the check accepts, so a kind the planner
# cannot write (or an unresolvable one) is Manual, with the kind named.
Describe 'Get-WoscapRemediationPlan registry kind (#29)' {
    It 'makes <Case> Manual and names the kind' -ForEach @(
        @{ Case = 'declared qword';        D = @{ Operator = 'eq'; Expected = [long]5;       Kind = 'qword' };        Match = 'QWord' }
        @{ Case = 'declared expandstring'; D = @{ Operator = 'eq'; Expected = '%SystemRoot%'; Kind = 'expandstring' }; Match = 'ExpandString' }
        @{ Case = 'declared multistring';  D = @{ Operator = 'setequals'; Expected = @('a'); Kind = 'multistring' };  Match = 'MultiString' }
        @{ Case = 'inferred multistring';  D = @{ Operator = 'sequence'; Expected = @('a', 'b') };                    Match = 'MultiString' }
        @{ Case = 'a resolver error';      D = @{ Operator = 'ge'; Expected = '5' };                                  Match = 'value kind is invalid' }
        @{ Case = 'an unknown Kind';       D = @{ Operator = 'eq'; Expected = 1; Kind = 'binary' };                   Match = 'value kind is invalid' }
    ) {
        InModuleScope woscap -Parameters @{ D = $D; Match = $Match } {
            param($D, $Match)
            $rules = @([pscustomobject]@{ StigId = 'R-1'; Title = 'r'; Status = 'Open' })
            $desc  = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N' } + $D
            $action = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack @{ 'R-1' = $desc })[0]
            $action.Type         | Should -Be 'Manual'
            $action.Automatable  | Should -BeFalse
            $action.ManualReason | Should -MatchExactly $Match
        }
    }
    It 'every automated Registry write is a kind the check accepts' {
        InModuleScope woscap {
            $written = @{ dword = 'DWord'; string = 'String' }
            foreach ($d in @(
                @{ Operator = 'eq'; Expected = 1 }
                @{ Operator = 'le'; Expected = 10; Kind = 'string' }
                @{ Operator = 'eq'; Expected = 'abc' }
                @{ Operator = 'ge'; Expected = 3; Kind = 'dword' }
            )) {
                $desc = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N' } + $d
                $action = @(Get-WoscapRemediationPlan -FailedRule @([pscustomobject]@{ StigId = 'R-1'; Title = 'r'; Status = 'Open' }) -ContentPack @{ 'R-1' = $desc })[0]
                $action.Automatable | Should -BeTrue
                @((Get-WoscapRequiredRegKind -Descriptor $desc).Kinds) | Should -Contain $written[$action.Registry.Kind]
            }
        }
    }
}

# Spec section 4 (#36): an All of automatable Registry leaves is one ordered multi-write fix.
Describe 'Get-WoscapRemediationPlan multi-write composites' {
    BeforeDiscovery {
        $ok = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\A'; Name = 'One'; Operator = 'eq'; Expected = 1 }
        $script:manualCases = @(
            @{ Case = 'nested composite child'; Child = @{ Type = 'All'; Checks = @($ok) } }
            @{ Case = 'non-Registry child';      Child = @{ Type = 'Path'; Path = 'C:\x'; Operator = 'eq'; Expected = $false } }
            @{ Case = 'HKCU leaf';               Child = @{ Type = 'Registry'; Path = 'HKCU:\Software\A'; Name = 'N'; Operator = 'eq'; Expected = 1 } }
            @{ Case = 'unwritable kind';         Child = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\A'; Name = 'N'; Operator = 'eq'; Expected = 1; Kind = 'qword' } }
            @{ Case = 'operator ne';             Child = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\A'; Name = 'N'; Operator = 'ne'; Expected = 1 } }
            @{ Case = 'operator in';             Child = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\A'; Name = 'N'; Operator = 'in'; Expected = @(1, 2) } }
            @{ Case = 'non-Int32 Expected';      Child = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\A'; Name = 'N'; Operator = 'eq'; Expected = [long]5000000000 } }
            @{ Case = 'child opted out';         Child = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\A'; Name = 'N'; Operator = 'eq'; Expected = 1; Remediate = $false } }
        )
    }
    It 'plans one automatable action whose writes follow the leaves in order' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'C-1'; Title = 'Multi'; Status = 'Open' })
            $pack = @{ 'C-1' = @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\A'; Name = 'One'; Operator = 'eq'; Expected = 1 }
                @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\B'; Name = 'Two'; Operator = 'eq'; Expected = 'x' }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\C'; Name = 'Three'; Operator = 'ge'; Expected = 7 }
            )} }
            $plan = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            $plan.Count | Should -Be 1
            $a = $plan[0]
            $a.Automatable | Should -BeTrue
            $a.Type | Should -Be 'Registry'
            $a.CheckType | Should -Be 'All'
            @($a.StigIds) | Should -Be @('C-1')
            @($a.Writes | ForEach-Object { "$($_.Path)|$($_.Name)|$($_.Data)|$($_.Kind)" }) |
                Should -Be @('HKLM:\SOFTWARE\A|One|1|dword', 'HKLM:\SOFTWARE\B|Two|x|string', 'HKLM:\SOFTWARE\C|Three|7|dword')
            # A consumer still reading the single-write field must fail loudly, not apply one write.
            $a.Registry | Should -BeNullOrEmpty
        }
    }
    It 'gives a single Registry rule one write equal to its Registry field' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'R-1'; Title = 't'; Status = 'Open' })
            $pack = @{ 'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\A'; Name = 'One'; Operator = 'eq'; Expected = 1 } }
            $a = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0]
            @($a.Writes).Count | Should -Be 1
            "$($a.Writes[0].Path)|$($a.Writes[0].Name)|$($a.Writes[0].Data)|$($a.Writes[0].Kind)" |
                Should -Be "$($a.Registry.Path)|$($a.Registry.Name)|$($a.Registry.Data)|$($a.Registry.Kind)"
        }
    }
    It 'stays Manual with its current reason for a <Case>' -ForEach $script:manualCases {
        InModuleScope woscap -Parameters @{ Child = $Child } {
            param($Child)
            $rules = @([pscustomobject]@{ StigId = 'C-2'; Title = 't'; Status = 'Open' })
            $ok = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\A'; Name = 'One'; Operator = 'eq'; Expected = 1 }
            $pack = @{ 'C-2' = @{ Type = 'All'; Checks = @($ok, $Child) } }
            $a = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)[0]
            $a.Automatable | Should -BeFalse
            $a.Type | Should -Be 'Manual'
            $a.ManualReason | Should -Be "CheckType 'All' has no automated remediation."
        }
    }
    It 'stays Manual for an Any composite, an empty All, and a parent Remediate = $false' {
        InModuleScope woscap {
            $ok = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\A'; Name = 'One'; Operator = 'eq'; Expected = 1 }
            $pack = @{
                'C-3' = @{ Type = 'Any'; Checks = @($ok, $ok) }
                'C-4' = @{ Type = 'All'; Checks = @() }
                'C-5' = @{ Type = 'All'; Checks = @($ok); Remediate = $false; RemediateReason = 'site policy' }
            }
            $rules = @('C-3', 'C-4', 'C-5' | ForEach-Object { [pscustomobject]@{ StigId = $_; Title = 't'; Status = 'Open' } })
            $plan = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            @($plan | Where-Object Automatable) | Should -BeNullOrEmpty
            ($plan | Where-Object StigId -eq 'C-5').ManualReason | Should -Match 'opts this rule out.*site policy'
        }
    }
}

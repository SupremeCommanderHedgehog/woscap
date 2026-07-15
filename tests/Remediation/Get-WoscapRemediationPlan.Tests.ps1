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
            $pack  = @{ 'R-2' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Expected = 'abc' } }
            (@(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack))[0].Registry.Kind | Should -Be 'string'
        }
    }
    It 'maps a Registry descriptor with a large (long) DWORD Expected to a dword action' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'R-3'; Title = 'Big dword'; Status = 'Open' })
            # 0xFFFFFFFF = 4294967295 exceeds Int32 range, so it loads as [long]
            $pack  = @{ 'R-3' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Expected = [long]4294967295 } }
            $plan  = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            $plan[0].Registry.Kind | Should -Be 'dword'
            $plan[0].Registry.Data | Should -Be 4294967295
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
    It 'returns an empty array for no failed rules' {
        InModuleScope woscap {
            @(Get-WoscapRemediationPlan -FailedRule @() -ContentPack @{}).Count | Should -Be 0
        }
    }
}

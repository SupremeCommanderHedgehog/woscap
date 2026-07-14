BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Expected = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/ansible/expected-playbook.yml'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'ConvertTo-AnsiblePlaybook' {
    It 'emits win_regedit and win_audit_policy_system tasks and a manual comment' {
        InModuleScope woscap -Parameters @{ Expected = $script:Expected } {
            $failed = @(
                [pscustomobject]@{ StigId = 'WN11-00-000032'; Title = 'MinimumPIN'; Status = 'Open' },
                [pscustomobject]@{ StigId = 'WN11-AU-000010'; Title = 'Credential Validation'; Status = 'Open' },
                [pscustomobject]@{ StigId = 'WN11-99-000001'; Title = 'Some manual-only rule'; Status = 'Open' }
            )
            $pack = @{
                'WN11-00-000032' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'; Name = 'MinimumPIN'; Operator = 'ge'; Expected = 6 }
                'WN11-AU-000010' = @{ Type = 'AuditPolicy'; Subcategory = 'Credential Validation'; Operator = 'includes'; Expected = 'Success' }
                'WN11-99-000001' = @{ Type = 'Script'; Script = { 'Fail' } }
            }
            $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack
            $expected = (Get-Content -LiteralPath $Expected -Raw) -replace "`r`n", "`n"
            ($text -replace "`r`n", "`n").TrimEnd() | Should -Be $expected.TrimEnd()
        }
    }
    It 'never emits a task for a passing rule' {
        InModuleScope woscap {
            $failed = @()   # caller passes only Open rules
            $pack = @{ 'X' = @{ Type = 'Registry'; Path = 'p'; Name = 'n'; Expected = 1 } }
            (ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack) | Should -Match 'hosts: all'
        }
    }
    It 'emits a # manual line (no throw, no task) for a Registry descriptor missing Expected' {
        InModuleScope woscap {
            $failed = @([pscustomobject]@{ StigId = 'WN11-XX-000001'; Title = 'Partial reg'; Status = 'Open' })
            $pack = @{ 'WN11-XX-000001' = @{ Type = 'Registry'; Path = 'p'; Name = 'n' } }  # no Expected
            $text = $null
            { $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack } | Should -Not -Throw
            $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack
            $text | Should -Match '# manual: WN11-XX-000001'
            $text | Should -Not -Match 'win_regedit'
        }
    }
    It 'merges paired Success+Failure rules for one subcategory into a single task' {
        InModuleScope woscap {
            $failed = @(
                [pscustomobject]@{ StigId = 'WN11-AU-000100'; Title = 'Logon Success'; Status = 'Open' },
                [pscustomobject]@{ StigId = 'WN11-AU-000101'; Title = 'Logon Failure'; Status = 'Open' }
            )
            $pack = @{
                'WN11-AU-000100' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Operator = 'includes'; Expected = 'Success' }
                'WN11-AU-000101' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Operator = 'includes'; Expected = 'Failure' }
            }
            $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack
            @($text -split "`n" | Where-Object { $_ -match 'win_audit_policy_system' }).Count | Should -Be 1
            # The name carries a colon, so it MUST be quoted or the YAML is invalid.
            $text | Should -Match 'name: "Audit policy: Logon"'
            $text | Should -Match 'audit_type: success and failure'
        }
    }
    It 'quotes an audit task name so the colon does not break YAML parsing' {
        InModuleScope woscap {
            $failed = @([pscustomobject]@{ StigId = 'WN11-AU-000010'; Title = 'Credential Validation'; Status = 'Open' })
            $pack = @{ 'WN11-AU-000010' = @{ Type = 'AuditPolicy'; Subcategory = 'Credential Validation'; Operator = 'includes'; Expected = 'Success' } }
            $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack
            $nameLine = @($text -split "`n" | Where-Object { $_ -match '^\s*- name:' })[-1]
            # An unquoted "Audit policy: <sub>" would embed a bare ': ' (YAML mapping
            # indicator). Require the value to be double-quoted.
            $nameLine | Should -Match ':\s*"[^"]*"\s*$'
        }
    }
    It 'emits a # manual line (no throw) when a descriptor is a bare scriptblock, not a hashtable' {
        InModuleScope woscap {
            $failed = @([pscustomobject]@{ StigId = 'WN11-XX-000002'; Title = 'Override rule'; Status = 'Open' })
            $pack = @{ 'WN11-XX-000002' = { 'Fail' } }  # bare scriptblock, no ContainsKey
            $text = $null
            { $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack } | Should -Not -Throw
            $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack
            $text | Should -Match '# manual: WN11-XX-000002'
        }
    }
}

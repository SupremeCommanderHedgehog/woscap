BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-WoscapRemediation' {
    It 'declares SupportsShouldProcess with ConfirmImpact High' {
        $attr = (Get-Command Invoke-WoscapRemediation).ScriptBlock.Attributes |
            Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
        $attr.SupportsShouldProcess | Should -BeTrue
        $attr.ConfirmImpact         | Should -Be 'High'
    }

    It 'with -WhatIf applies nothing and marks automatable rules Planned' {
        InModuleScope woscap {
            Mock Import-ContentPack { @{ 'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Expected = 1 } } }
            Mock Test-Path { $true }
            Mock Set-WoscapRegValue {}
            Mock Invoke-AuditPolSet {}
            Mock Test-Descriptor { [pscustomobject]@{ Result = 'Pass'; Observed = 1; Expected = 1 } }
            $rules = @([pscustomobject]@{ StigId = 'R-1'; Title = 'Reg'; Status = 'Open' })
            $out = @($rules | Invoke-WoscapRemediation -ContentPath 'TestDrive:\pack' -WhatIf -Quiet)
            Should -Invoke Set-WoscapRegValue -Exactly 0
            $out.Count     | Should -Be 1
            $out[0].State  | Should -Be 'Planned'
        }
    }

    It 'processes only Open rules' {
        InModuleScope woscap {
            Mock Import-ContentPack { @{
                'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Expected = 1 }
                'R-2' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'M'; Expected = 1 }
            } }
            Mock Test-Path { $true }
            Mock Set-WoscapRegValue {}
            Mock Test-Descriptor { [pscustomobject]@{ Result = 'Pass'; Observed = 1; Expected = 1 } }
            $rules = @(
                [pscustomobject]@{ StigId = 'R-1'; Title = 'Open one';  Status = 'Open' },
                [pscustomobject]@{ StigId = 'R-2'; Title = 'Clean one'; Status = 'NotAFinding' }
            )
            $out = @($rules | Invoke-WoscapRemediation -ContentPath 'TestDrive:\pack' -Force -Quiet)
            $out.Count      | Should -Be 1
            $out[0].StigId  | Should -Be 'R-1'
        }
    }

    It 'applies, re-checks, and flips After to NotAFinding on success' {
        InModuleScope woscap {
            Mock Import-ContentPack { @{ 'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Expected = 1 } } }
            Mock Test-Path { $true }
            Mock Set-WoscapRegValue {}
            Mock Test-Descriptor { [pscustomobject]@{ Result = 'Pass'; Observed = 1; Expected = 1 } }
            $rules = @([pscustomobject]@{ StigId = 'R-1'; Title = 'Reg'; Status = 'Open' })
            $out = @($rules | Invoke-WoscapRemediation -ContentPath 'TestDrive:\pack' -Force -Quiet)
            Should -Invoke Set-WoscapRegValue -Exactly 1
            $out[0].State | Should -Be 'Applied'
            $out[0].After | Should -Be 'NotAFinding'
        }
    }

    It 'isolates an apply failure as Failed and still completes the batch' {
        InModuleScope woscap {
            Mock Import-ContentPack { @{
                'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Expected = 1 }
                'R-2' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'M'; Expected = 1 }
            } }
            Mock Test-Path { $true }
            Mock Set-WoscapRegValue { if ($Name -eq 'N') { throw 'access denied' } }
            Mock Test-Descriptor { [pscustomobject]@{ Result = 'Pass'; Observed = 1; Expected = 1 } }
            $rules = @(
                [pscustomobject]@{ StigId = 'R-1'; Title = 'Fails';  Status = 'Open' },
                [pscustomobject]@{ StigId = 'R-2'; Title = 'Works';  Status = 'Open' }
            )
            $out = @($rules | Invoke-WoscapRemediation -ContentPath 'TestDrive:\pack' -Force -Quiet)
            $out.Count | Should -Be 2
            ($out | Where-Object StigId -eq 'R-1').State  | Should -Be 'Failed'
            ($out | Where-Object StigId -eq 'R-1').Detail | Should -Match 'access denied'
            ($out | Where-Object StigId -eq 'R-2').State  | Should -Be 'Applied'
        }
    }

    It 'reports an unsupported CheckType as Manual and writes nothing' {
        InModuleScope woscap {
            Mock Import-ContentPack { @{ 'S-1' = @{ Type = 'Service'; Name = 'W32Time' } } }
            Mock Test-Path { $true }
            Mock Set-WoscapRegValue {}
            Mock Invoke-AuditPolSet {}
            $rules = @([pscustomobject]@{ StigId = 'S-1'; Title = 'Svc'; Status = 'Open' })
            $out = @($rules | Invoke-WoscapRemediation -ContentPath 'TestDrive:\pack' -Force -Quiet)
            Should -Invoke Set-WoscapRegValue -Exactly 0
            Should -Invoke Invoke-AuditPolSet -Exactly 0
            $out[0].State | Should -Be 'Manual'
            $out[0].Detail | Should -Match 'no automated remediation'
        }
    }

    It 'with -WhatIf emits one Planned row per automatable rule' {
        InModuleScope woscap {
            Mock Import-ContentPack { @{
                'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Expected = 1 }
                'R-2' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'M'; Expected = 1 }
            } }
            Mock Test-Path { $true }
            Mock Set-WoscapRegValue {}
            $rules = @(
                [pscustomobject]@{ StigId = 'R-1'; Title = 'One'; Status = 'Open' },
                [pscustomobject]@{ StigId = 'R-2'; Title = 'Two'; Status = 'Open' }
            )
            $out = @($rules | Invoke-WoscapRemediation -ContentPath 'TestDrive:\pack' -WhatIf -Quiet)
            Should -Invoke Set-WoscapRegValue -Exactly 0
            $out.Count | Should -Be 2
            @($out | Where-Object State -eq 'Planned').Count | Should -Be 2
        }
    }

    It 'applies an AuditPolicy subcategory with the aggregated directions' {
        InModuleScope woscap {
            Mock Import-ContentPack { @{
                'A-1' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Expected = 'Success' }
                'A-2' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Expected = 'Failure' }
            } }
            Mock Test-Path { $true }
            Mock Invoke-AuditPolSet {}
            Mock Test-Descriptor { [pscustomobject]@{ Result = 'Pass'; Observed = 'Success and Failure'; Expected = 'Success' } }
            $rules = @(
                [pscustomobject]@{ StigId = 'A-1'; Title = 'Logon S'; Status = 'Open' },
                [pscustomobject]@{ StigId = 'A-2'; Title = 'Logon F'; Status = 'Open' }
            )
            $out = @($rules | Invoke-WoscapRemediation -ContentPath 'TestDrive:\pack' -Force -Quiet)
            Should -Invoke Invoke-AuditPolSet -Exactly 1 -ParameterFilter {
                $Subcategory -eq 'Logon' -and $Success -eq $true -and $Failure -eq $true
            }
            @($out | Where-Object State -eq 'Applied').Count | Should -Be 1
        }
    }

    # These deliberately do NOT mock Test-Descriptor. Every other test here
    # mocks it wholesale, which is exactly why the read-cache regression below
    # was invisible: the post-fix re-check never actually re-read anything.
    Context 'post-fix re-check reads current state, not the cached pre-fix snapshot' {
        It 'reports an applied audit fix as NotAFinding, not still-Open' {
            InModuleScope woscap {
                Clear-WoscapReadCache
                Mock Import-ContentPack { @{ 'A-1' = @{ Type='AuditPolicy'; Subcategory='Logon'; Operator='includes'; Expected='Success' } } }
                Mock Test-Path { $true }

                # auditpol reports the pre-fix state until Invoke-AuditPolSet runs.
                $script:auditFixed = $false
                Mock Invoke-AuditPolSet { $script:auditFixed = $true }
                Mock Invoke-AuditPolRaw {
                    if ($script:auditFixed) { 'fixed' } else { 'unfixed' }
                }
                Mock ConvertFrom-AuditPolCsv {
                    if ($CsvText -eq 'fixed') { @{ 'Logon' = @('Success') } } else { @{ 'Logon' = @('No Auditing') } }
                }

                # Simulate the documented scan-then-remediate flow: the scan
                # populates the cache with the pre-fix reading first.
                $null = Get-AuditPolicy -Subcategory 'Logon'

                $rules = @([pscustomobject]@{ StigId='A-1'; Title='Logon S'; Status='Open' })
                $out = @($rules | Invoke-WoscapRemediation -ContentPath 'TestDrive:\pack' -Force -Quiet)
                $out[0].State | Should -Be 'Applied'
                $out[0].After | Should -Be 'NotAFinding' -Because 'a stale cached auditpol read would report Open for a fix that was applied'
            }
        }

        It 'reports an applied registry fix as NotAFinding' {
            InModuleScope woscap {
                Clear-WoscapReadCache
                Mock Import-ContentPack { @{ 'R-1' = @{ Type='Registry'; Path='HKLM:\S'; Name='N'; Operator='eq'; Expected=1 } } }
                Mock Test-Path { $true }
                $script:regFixed = $false
                Mock Set-WoscapRegValue { $script:regFixed = $true }
                Mock Get-ItemProperty { if ($script:regFixed) { [pscustomobject]@{ N = 1 } } else { [pscustomobject]@{ N = 0 } } }

                $rules = @([pscustomobject]@{ StigId='R-1'; Title='Reg'; Status='Open' })
                $out = @($rules | Invoke-WoscapRemediation -ContentPath 'TestDrive:\pack' -Force -Quiet)
                $out[0].State | Should -Be 'Applied'
                $out[0].After | Should -Be 'NotAFinding'
            }
        }
    }
}

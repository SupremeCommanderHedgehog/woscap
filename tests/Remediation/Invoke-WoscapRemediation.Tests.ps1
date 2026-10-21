BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'helpers/New-WoscapTestRegEntry.ps1')
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
            Mock Import-ContentPack { @{ 'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = 'eq'; Expected = 1 } } }
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

    It 'with -Force never writes a Registry rule whose operator has no safe value (#23)' {
        InModuleScope woscap {
            Mock Import-ContentPack { @{
                'R-NE' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = 'ne'; Expected = 0 }
                'R-RX' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'T'; Operator = 'regex'; Expected = '\S' }
            } }
            Mock Test-Path { $true }
            Mock Set-WoscapRegValue {}
            Mock Invoke-AuditPolSet {}
            Mock Test-Descriptor { [pscustomobject]@{ Result = 'Pass'; Observed = 1; Expected = 1 } }
            $rules = @('R-NE', 'R-RX' | ForEach-Object { [pscustomobject]@{ StigId = $_; Title = $_; Status = 'Open' } })
            $out = @(Invoke-WoscapRemediation -Result $rules -ContentPath 'TestDrive:\pack' -Force -Quiet)
            Should -Invoke Set-WoscapRegValue -Exactly 0
            @($out | Where-Object { $_.State -eq 'Manual' }).Count | Should -Be 2
        }
    }

    It 'describes an audit fix as enabling directions, since nothing is ever disabled' {
        InModuleScope woscap {
            Mock Import-ContentPack { @{
                'A-1' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Expected = 'Success' }
                'A-2' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Expected = 'Failure' }
            } }
            Mock Test-Path { $true }
            Mock Set-WoscapRegValue {}
            Mock Invoke-AuditPolSet {}
            $rules = @('A-1', 'A-2' | ForEach-Object { [pscustomobject]@{ StigId = $_; Title = $_; Status = 'Open' } })
            $out = @(Invoke-WoscapRemediation -Result $rules -ContentPath 'TestDrive:\pack' -WhatIf -Quiet)
            $out[0].Action | Should -BeExactly "Enable audit 'Logon': success and failure"
            Should -Invoke Invoke-AuditPolSet -Exactly 0
        }
    }

    It 'processes only Open rules' {
        InModuleScope woscap {
            Mock Import-ContentPack { @{
                'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = 'eq'; Expected = 1 }
                'R-2' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'M'; Operator = 'eq'; Expected = 1 }
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
            Mock Import-ContentPack { @{ 'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = 'eq'; Expected = 1 } } }
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
                'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = 'eq'; Expected = 1 }
                'R-2' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'M'; Operator = 'eq'; Expected = 1 }
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
                'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = 'eq'; Expected = 1 }
                'R-2' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'M'; Operator = 'eq'; Expected = 1 }
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
                Mock Get-RegValueEntry { New-WoscapTestRegEntry $(if ($script:regFixed) { 1 } else { 0 }) }

                $rules = @([pscustomobject]@{ StigId='R-1'; Title='Reg'; Status='Open' })
                $out = @($rules | Invoke-WoscapRemediation -ContentPath 'TestDrive:\pack' -Force -Quiet)
                $out[0].State | Should -Be 'Applied'
                $out[0].After | Should -Be 'NotAFinding'
            }
        }
    }
}

Describe 'Invoke-WoscapRemediation refuses under WOW64' {
    It 'refuses <Name> before planning or writing' -ForEach @(
        @{ Name = 'default';  Extra = @{} }
        @{ Name = '-WhatIf';  Extra = @{ WhatIf = $true } }
        @{ Name = '-Force';   Extra = @{ Force = $true } }
    ) {
        InModuleScope woscap -Parameters @{ Extra = $Extra } {
            param($Extra)
            Mock Test-WoscapWow64Process { $true }
            Mock Get-WoscapRemediationPlan { throw 'must not plan' }
            Mock Set-WoscapRegValue { throw 'must not write' }
            Mock Invoke-AuditPolSet { throw 'must not write' }
            $open = [pscustomobject]@{ StigId = 'X-1'; Status = 'Open' }
            { $open | Invoke-WoscapRemediation @Extra } | Should -Throw -ExpectedMessage $script:WoscapWow64RefusalMessage
            Should -Invoke Get-WoscapRemediationPlan -Times 0 -Exactly
            Should -Invoke Set-WoscapRegValue -Times 0 -Exactly
            Should -Invoke Invoke-AuditPolSet -Times 0 -Exactly
        }
    }
}

# Spec 5 / 7.4 (#36): a multi-write fix applies every write in order and stops at the first failure.
Describe 'Invoke-WoscapRemediation multi-write fixes' {
    BeforeEach {
        InModuleScope woscap {
            $script:multiPack = @{ 'C-1' = @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\A'; Name = 'One'; Operator = 'eq'; Expected = 1 }
                @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\B'; Name = 'Two'; Operator = 'eq'; Expected = 'x' }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\C'; Name = 'Three'; Operator = 'eq'; Expected = 3 }
            )} }
            $script:written = [System.Collections.Generic.List[string]]::new()
            $script:failOn = ''
            Mock Import-ContentPack { $script:multiPack }
            Mock Test-Path { $true }
            Mock New-Item {}
            Mock Set-ItemProperty {}
            Mock Set-WoscapRegValue {
                if ("$Path\$Name" -eq $script:failOn) { throw 'access denied' }
                $script:written.Add("$Path\$Name=$Data($Kind)")
            }
            Mock Test-Descriptor { [pscustomobject]@{ Result = 'Pass'; Observed = 1; Expected = 1 } }
        }
    }

    It 'applies every write in order, then re-checks the whole rule once' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'C-1'; Title = 'Multi'; Status = 'Open' })
            $out = @(Invoke-WoscapRemediation -Result $rules -ContentPath 'TestDrive:\pack' -Force -Quiet)
            @($script:written) | Should -Be @('HKLM:\SOFTWARE\A\One=1(dword)', 'HKLM:\SOFTWARE\B\Two=x(string)', 'HKLM:\SOFTWARE\C\Three=3(dword)')
            $out.Count | Should -Be 1
            $out[0].State | Should -Be 'Applied'
            $out[0].After | Should -Be 'NotAFinding'
            $out[0].CheckType | Should -Be 'All'
            Should -Invoke Test-Descriptor -Exactly 1 -ParameterFilter { $Descriptor.Type -eq 'All' }
        }
    }

    It 'stops at the first failed write and names what succeeded, failed and was not attempted' {
        InModuleScope woscap {
            $script:failOn = 'HKLM:\SOFTWARE\B\Two'
            $rules = @([pscustomobject]@{ StigId = 'C-1'; Title = 'Multi'; Status = 'Open' })
            $out = @(Invoke-WoscapRemediation -Result $rules -ContentPath 'TestDrive:\pack' -Force -Quiet)
            @($script:written) | Should -Be @('HKLM:\SOFTWARE\A\One=1(dword)')
            Should -Invoke Set-WoscapRegValue -Exactly 0 -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\C' }
            $out[0].State | Should -Be 'Failed'
            $out[0].Detail | Should -Match ([regex]::Escape('Succeeded: HKLM:\SOFTWARE\A\One'))
            $out[0].Detail | Should -Match ([regex]::Escape('Failed: HKLM:\SOFTWARE\B\Two'))
            $out[0].Detail | Should -Match 'access denied'
            $out[0].Detail | Should -Match ([regex]::Escape('Not attempted: HKLM:\SOFTWARE\C\Three'))
        }
    }

    It 'with -WhatIf writes nothing and its one ShouldProcess action lists every write' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ StigId = 'C-1'; Title = 'Multi'; Status = 'Open' })
            $out = @(Invoke-WoscapRemediation -Result $rules -ContentPath 'TestDrive:\pack' -WhatIf -Quiet)
            Should -Invoke Set-WoscapRegValue -Exactly 0
            Should -Invoke Set-ItemProperty -Exactly 0
            $out.Count | Should -Be 1
            $out[0].State | Should -Be 'Planned'
            $out[0].Action | Should -BeExactly 'Set HKLM:\SOFTWARE\A\One = 1 (dword); Set HKLM:\SOFTWARE\B\Two = x (string); Set HKLM:\SOFTWARE\C\Three = 3 (dword)'
        }
    }

    It 'keeps the single-write action text unchanged' {
        InModuleScope woscap {
            $script:multiPack = @{ 'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'N'; Operator = 'eq'; Expected = 1 } }
            $rules = @([pscustomobject]@{ StigId = 'R-1'; Title = 'Reg'; Status = 'Open' })
            $out = @(Invoke-WoscapRemediation -Result $rules -ContentPath 'TestDrive:\pack' -WhatIf -Quiet)
            $out[0].Action | Should -BeExactly 'Set HKLM:\S\N = 1 (dword)'
        }
    }
}

# A write keeps an existing value's stored name case, so an exact-case rule must re-check as Open.
Describe 'Invoke-WoscapRemediation with NameCase Exact over a differently cased value' {
    It 'reports After Open, never NotAFinding, when Locked already exists as locked' {
        InModuleScope woscap {
            $key = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EncryptedMediaExtensions'
            $script:emePack = @{ 'FFOX-00-000037' = @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; NameCase = 'Exact'; Path = $key; Name = 'Enabled'; Operator = 'eq'; Expected = 0 }
                @{ Type = 'Registry'; NameCase = 'Exact'; Path = $key; Name = 'Locked'; Operator = 'eq'; Expected = 1 }
            )} }
            Mock Import-ContentPack { $script:emePack }
            # In-memory key: stored name -> value. Like the registry, a write to an existing
            # name in any case updates the value and keeps the stored name.
            $script:store = [ordered]@{ 'locked' = 0 }
            Mock Test-Path { $true }
            Mock New-Item {}
            Mock Set-ItemProperty {
                $hit = @($script:store.Keys | Where-Object { $_ -eq $Name })
                if ($hit.Count -gt 0) { $script:store[$hit[0]] = $Value } else { $script:store[$Name] = $Value }
            }
            Mock Get-RegValueEntry {
                $hit = @($script:store.Keys | Where-Object { if ($ExactNameCase) { $_ -ceq $Name } else { $_ -eq $Name } })
                if ($hit.Count -eq 0) { return $null }
                [pscustomobject]@{ Value = [int]$script:store[$hit[0]]; Kind = 'DWord' }
            }
            $rules = @([pscustomobject]@{ StigId = 'FFOX-00-000037'; Title = 'EME'; Status = 'Open' })
            $out = @(Invoke-WoscapRemediation -Result $rules -ContentPath 'TestDrive:\pack' -Force -Quiet)
            Should -Invoke Set-ItemProperty -Exactly 2
            @($script:store.Keys) | Should -Be @('locked', 'Enabled') -Because 'the stored case survives the write'
            $script:store['locked'] | Should -Be 1
            $out[0].State | Should -Be 'Applied'
            $out[0].After | Should -Be 'Open'
        }
    }
}

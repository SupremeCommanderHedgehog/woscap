BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

# The GUI confirms remediation per preview row, then applies only the findings named by the
# ticked rows' StigIds. This proves, for every tick subset and two input orders, that the
# writes performed are exactly the ticked rows' actions: none extra, none missing, none altered.
Describe 'Remediation selection invariant' {
    It 'applies exactly the ticked preview rows for every subset (<Order> input order)' -ForEach @(
        @{ Order = 'forward' }, @{ Order = 'reverse' }
    ) {
        InModuleScope woscap -Parameters @{ Order = $Order } {
            param($Order)
            Mock Import-ContentPack { @{
                'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'A'; Operator = 'eq'; Expected = 1 }
                'R-2' = @{ Type = 'Registry'; Path = 'HKLM:\S'; Name = 'B'; Operator = 'eq'; Expected = 'x' }
                'A-1' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon';  Expected = 'Success' }
                'A-2' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon';  Expected = 'Failure' }
                'A-3' = @{ Type = 'AuditPolicy'; Subcategory = 'Logoff'; Expected = 'Success' }
                'M-1' = @{ Type = 'Service'; Name = 'svc'; Expected = 'Disabled' }
            } }
            Mock Test-Path { $true }
            Mock Test-Descriptor { [pscustomobject]@{ Result = 'Pass'; Observed = 1; Expected = 1 } }
            $script:writes = [System.Collections.Generic.List[string]]::new()
            # Rebuild each write in the exact format of the cmdlet's Action text.
            Mock Set-WoscapRegValue { $script:writes.Add("Set $Path\$Name = $Data ($Kind)") }
            Mock Invoke-AuditPolSet {
                $d = @()
                if ($Success) { $d += 'success' }
                if ($Failure) { $d += 'failure' }
                $script:writes.Add("Enable audit '$Subcategory': $($d -join ' and ')")
            }

            $ids = @('R-1', 'R-2', 'A-1', 'A-2', 'A-3', 'M-1')
            if ($Order -eq 'reverse') { [array]::Reverse($ids) }
            $findings = @($ids | ForEach-Object { [pscustomobject]@{ StigId = $_; Title = $_; Status = 'Open' } })

            $preview = @(Invoke-WoscapRemediation -Result $findings -ContentPath 'TestDrive:\pack' -WhatIf -Quiet)
            $planned = @($preview | Where-Object { $_.State -eq 'Planned' })
            $planned.Count | Should -Be 4 -Because 'R-1, R-2, Logon (A-1+A-2), Logoff (A-3)'
            @($preview | Where-Object { $_.State -eq 'Manual' }).Count | Should -Be 1

            for ($mask = 0; $mask -lt (1 -shl $planned.Count); $mask++) {
                $ticked = @(for ($i = 0; $i -lt $planned.Count; $i++) {
                    if ($mask -band (1 -shl $i)) { $planned[$i] }
                })
                $tickedIds = @($ticked | ForEach-Object { $_.StigIds })
                $subset = @($findings | Where-Object { $_.StigId -in $tickedIds })

                $script:writes.Clear()
                $applied = @(Invoke-WoscapRemediation -Result $subset -ContentPath 'TestDrive:\pack' -Force -Quiet)

                $expected = (@($ticked | ForEach-Object { $_.Action }) | Sort-Object) -join '|'
                (@($script:writes) | Sort-Object) -join '|' | Should -Be $expected -Because "writes for mask $mask"
                (@($applied | Where-Object { $_.State -eq 'Applied' } | ForEach-Object { $_.Action }) | Sort-Object) -join '|' |
                    Should -Be $expected -Because "Applied rows for mask $mask"
            }
        }
    }
}

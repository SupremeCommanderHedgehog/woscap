BeforeDiscovery {
    $root = Split-Path $PSScriptRoot -Parent | Split-Path -Parent
    Import-Module (Join-Path $root 'woscap.psd1') -Force
    # Discovered dynamically so a newly shipped pack is covered without editing this file.
    $script:packCases = @(Get-ChildItem -LiteralPath (Join-Path $root 'Content') -Directory |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'checks.psd1') } |
        ForEach-Object { @{ Pack = $_.Name; Dir = $_.FullName } })
    $script:ruleCases = foreach ($p in $script:packCases) {
        # Loaded exactly as Invoke-WoscapRemediation loads it, overrides included.
        $data = & (Get-Module woscap) { param($d) Import-ContentPack -Path $d -WarningAction SilentlyContinue } $p.Dir
        foreach ($key in @($data.Keys | Sort-Object)) {
            $d = $data[$key]
            if ($d -is [hashtable] -and $d.ContainsKey('Type') -and [string]$d.Type -in @('Registry', 'All')) {
                @{ Pack = $p.Pack; StigId = $key; Descriptor = $d }
            }
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'helpers/New-WoscapTestRegEntry.ps1')
    $script:MainBaseline = Import-PowerShellDataFile -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/remediation/automated-main-bdce070.psd1')
    # The only changes #36 may make to what is automated: composites of automatable leaves.
    $script:NewIn36 = @{
        AcrobatReader = @('ARDC-CN-000005', 'ARDC-CN-000010', 'ARDC-CN-000015', 'ARDC-CN-000020', 'ARDC-CN-000030',
            'ARDC-CN-000035', 'ARDC-CN-000045', 'ARDC-CN-000050', 'ARDC-CN-000055', 'ARDC-CN-000060', 'ARDC-CN-000065',
            'ARDC-CN-000075', 'ARDC-CN-000080', 'ARDC-CN-000085', 'ARDC-CN-000090', 'ARDC-CN-000115', 'ARDC-CN-000120',
            'ARDC-CN-000315', 'ARDC-CN-000320')
        Firefox       = @('FFOX-00-000009', 'FFOX-00-000017', 'FFOX-00-000029', 'FFOX-00-000037')
        Windows11     = @('WN11-CC-000039', 'WN11-CC-000210')
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

# Invariant (#23, #36): the planner may only automate a rule when applying ALL its writes makes
# the SAME descriptor pass under the real Test-Descriptor - for every value of every machine
# fact a child's Applicability depends on.
Describe 'Remediation plan soundness over shipped content' {
    It '<Pack> <StigId>: the planned writes make the rule pass' -ForEach $script:ruleCases {
        InModuleScope woscap -Parameters @{ StigId = $StigId; Descriptor = $Descriptor } {
            param($StigId, $Descriptor)
            $rule = [pscustomobject]@{ StigId = $StigId; Title = $StigId; Status = 'Open' }
            $plan = @(Get-WoscapRemediationPlan -FailedRule @($rule) -ContentPack @{ $StigId = $Descriptor })
            $plan.Count | Should -Be 1
            $action = $plan[0]
            if (-not $action.Automatable) {
                $action.Type | Should -Be 'Manual'
                $action.ManualReason | Should -Not -BeNullOrEmpty
                return
            }
            $action.Type | Should -Be 'Registry'
            $leaves = @(if ($Descriptor.Type -eq 'All') { $Descriptor.Checks } else { $Descriptor })
            $writes = @($action.Writes)
            $writes.Count | Should -Be $leaves.Count -Because 'every leaf must be written'

            # Model the real read-back, kind included: REG_DWORD reads as DWord Int32, REG_SZ as String.
            $script:store = @{}
            for ($i = 0; $i -lt $writes.Count; $i++) {
                $w = $writes[$i]; $leaf = $leaves[$i]
                $w.Path | Should -Be ([string]$leaf.Path)
                $w.Name | Should -BeExactly ([string]$leaf.Name)
                # The elevated writer's HKCU is not the audited user's hive.
                $w.Path | Should -Not -Match '^(HKCU:|(Microsoft\.PowerShell\.Core\\)?Registry::HKEY_CURRENT_USER)'
                if ($leaf.ContainsKey('Kind')) { $w.Kind | Should -Be ([string]$leaf.Kind) -Because 'a write must keep the declared registry type' }
                $script:store["$($w.Path)|$($w.Name)"] = switch ($w.Kind) {
                    'dword' {
                        $n = [long]$w.Data
                        if ($n -lt [int]::MinValue -or $n -gt [int]::MaxValue) { throw "dword out of Int32 range: $n" }
                        New-WoscapTestRegEntry ([int]$n) -Kind DWord
                    }
                    'string' {
                        $w.Data | Should -BeOfType [string]
                        New-WoscapTestRegEntry ([string]$w.Data) -Kind String
                    }
                    default { throw "unknown Kind '$($w.Kind)'" }
                }
            }
            Mock Get-RegValueEntry { $k = "$Path|$Name"; if ($script:store.ContainsKey($k)) { $script:store[$k] } else { $null } }

            # Facts gating a child decide whether that child votes, so each must be exercised.
            # The planner admits exactly these gates (R2, R8); anything else must not reach here.
            $boolFacts = @($script:WoscapBooleanFacts)
            $children = @(if ($Descriptor.Type -eq 'All') { $leaves })
            $facts = @($children | Where-Object { $_.ContainsKey('Applicability') } | ForEach-Object { @($_.Applicability.Keys) } | Sort-Object -Unique)
            $unmodelled = @($facts | Where-Object { $_ -notin $boolFacts })
            if ($unmodelled.Count) { throw "soundness guard cannot model child predicate(s): $($unmodelled -join ', ')" }
            if ($facts.Count -eq 0) {
                Mock Test-WoscapApplicability { [pscustomobject]@{ Applies = $true; Unreadable = $false; Reason = '' } }
                (Test-Descriptor -Descriptor $Descriptor).Result | Should -Be 'Pass'
                return
            }
            # A root gate only decides whether the rule applies at all; the children are under test.
            $subject = $Descriptor.Clone(); $subject.Remove('Applicability')
            Mock Get-WoscapMachineFact { $script:combo[$Fact] }
            for ($mask = 0; $mask -lt [math]::Pow(2, $facts.Count); $mask++) {
                $script:combo = @{}
                for ($b = 0; $b -lt $facts.Count; $b++) { $script:combo[$facts[$b]] = [bool]($mask -band (1 -shl $b)) }
                $label = ($facts | ForEach-Object { "$_=$($script:combo[$_])" }) -join ', '
                (Test-Descriptor -Descriptor $subject).Result | Should -Be 'Pass' -Because "the writes must satisfy the rule when $label"
            }
        }
    }

    It '<Pack>: automates exactly main''s fixes plus the #36 composites (guard is not vacuous)' -ForEach $script:packCases {
        InModuleScope woscap -Parameters @{ Pack = $Pack; Dir = $Dir; Baseline = $script:MainBaseline; NewIn36 = $script:NewIn36 } {
            param($Pack, $Dir, $Baseline, $NewIn36)
            $Baseline.ContainsKey($Pack) | Should -BeTrue -Because 'a new pack must add its automated list to the baseline fixture'
            $added = @(if ($NewIn36.ContainsKey($Pack)) { $NewIn36[$Pack] })
            $want = @(@($Baseline[$Pack].StigIds) + $added | Sort-Object)
            $data = Import-ContentPack -Path $Dir -WarningAction SilentlyContinue
            $rules = @($data.Keys | ForEach-Object { [pscustomobject]@{ StigId = $_; Title = $_; Status = 'Open' } })
            $auto = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $data | Where-Object { $_.Automatable })
            @($auto | ForEach-Object { $_.StigIds } | Sort-Object) | Should -Be $want
            $auto.Count | Should -Be ($Baseline[$Pack].Actions + $added.Count)
            if ($want.Count -eq 0) { Set-ItResult -Skipped -Because 'the pack automates nothing, as on main'; return }
        }
    }

    It 'AcrobatReader: the two opted-out rules stay Manual through Remediate = $false' {
        InModuleScope woscap {
            $data = Import-ContentPack -Path (Join-Path $script:WoscapModuleRoot 'Content\AcrobatReader') -WarningAction SilentlyContinue
            foreach ($id in 'ARDC-CN-000025', 'ARDC-CN-000100') {
                $data[$id].Remediate | Should -BeExactly $false
                $a = @(Get-WoscapRemediationPlan -FailedRule @([pscustomobject]@{ StigId = $id; Title = $id; Status = 'Open' }) -ContentPack $data)[0]
                $a.Automatable | Should -BeFalse
                $a.ManualReason | Should -Match 'opts this rule out'
            }
        }
    }

    It 'WN11-SO-000085 declares REG_SZ, so its fix is written as the string 10' {
        InModuleScope woscap {
            $root = $script:WoscapModuleRoot
            $data = Import-ContentPack -Path (Join-Path $root 'Content\Windows11') -WarningAction SilentlyContinue
            $data['WN11-SO-000085'].Kind | Should -Be 'string'
            $rule = [pscustomobject]@{ StigId = 'WN11-SO-000085'; Title = 't'; Status = 'Open' }
            $action = @(Get-WoscapRemediationPlan -FailedRule @($rule) -ContentPack $data)[0]
            $action.Writes[0].Kind | Should -Be 'string'
            $action.Writes[0].Data | Should -BeOfType [string]
            $action.Writes[0].Data | Should -Be '10'
        }
    }
}

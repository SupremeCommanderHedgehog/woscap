BeforeDiscovery {
    $root = Split-Path $PSScriptRoot -Parent | Split-Path -Parent
    # Discovered dynamically so a newly shipped pack is covered without editing this file.
    $script:packCases = @(Get-ChildItem -LiteralPath (Join-Path $root 'Content') -Directory |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'checks.psd1') } |
        ForEach-Object { @{ Pack = $_.Name; File = (Join-Path $_.FullName 'checks.psd1') } })
    $script:ruleCases = foreach ($p in $script:packCases) {
        $data = Import-PowerShellDataFile -LiteralPath $p.File
        foreach ($key in @($data.Keys | Sort-Object)) {
            $d = $data[$key]
            if ($d -is [hashtable] -and $d.ContainsKey('Type') -and [string]$d.Type -eq 'Registry') {
                @{ Pack = $p.Pack; StigId = $key; Descriptor = $d }
            }
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

# Invariant (#23): the planner may only automate a Registry write when writing that Data
# with that Kind makes the SAME descriptor pass under the real Test-Descriptor.
Describe 'Remediation plan soundness over shipped content' {
    It '<Pack> <StigId>: a planned Registry write makes the rule pass' -ForEach $script:ruleCases {
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
            $action.Type          | Should -Be 'Registry'
            $action.Registry.Path | Should -Be ([string]$Descriptor.Path)
            $action.Registry.Name | Should -Be ([string]$Descriptor.Name)

            # Model the real read-back: REG_DWORD comes back as Int32, REG_SZ as String.
            $data = $action.Registry.Data
            $script:readBack = switch ($action.Registry.Kind) {
                'dword' {
                    $n = [long]$data
                    if ($n -lt 0 -or $n -gt [uint32]::MaxValue) { throw "dword out of range: $n" }
                    if ($n -gt [int]::MaxValue) { [int]($n - 4294967296) } else { [int]$n }
                }
                'string' { [string]$data }
                default  { throw "unknown Kind '$($action.Registry.Kind)'" }
            }
            $script:regPath = $action.Registry.Path
            $script:regName = $action.Registry.Name
            Mock Get-RegValue { $null }
            Mock Get-RegValue { $script:readBack } -ParameterFilter { $Path -eq $script:regPath -and $Name -eq $script:regName }
            Mock Test-WoscapApplicability { [pscustomobject]@{ Applies = $true; Unreadable = $false; Reason = '' } }

            $verdict = Test-Descriptor -Descriptor $Descriptor
            $verdict.Result | Should -Be 'Pass' -Because "writing $data ($($action.Registry.Kind)) must satisfy operator '$($Descriptor.Operator)'"
        }
    }

    It '<Pack>: still automates at least one Registry rule (guard is not vacuous)' -ForEach $script:packCases {
        InModuleScope woscap -Parameters @{ File = $File } {
            param($File)
            $data = Import-PowerShellDataFile -LiteralPath $File
            $ids = @($data.Keys | Where-Object { $data[$_] -is [hashtable] -and [string]$data[$_].Type -eq 'Registry' })
            if ($ids.Count -eq 0) { Set-ItResult -Skipped -Because 'pack has no Registry rules'; return }
            $rules = @($ids | ForEach-Object { [pscustomobject]@{ StigId = $_; Title = $_; Status = 'Open' } })
            $plan = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $data)
            @($plan | Where-Object { $_.Automatable }).Count | Should -BeGreaterThan 0
        }
    }
}

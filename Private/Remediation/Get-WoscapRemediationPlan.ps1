function Get-WoscapRemediationPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $FailedRule,
        [Parameter(Mandatory)] [hashtable] $ContentPack
    )

    $newManual = {
        param($StigId, $Title, $CheckType, $Reason)
        [pscustomobject]@{
            StigId = $StigId; StigIds = @($StigId); Title = $Title; Type = 'Manual'; CheckType = $CheckType
            Automatable = $false; Registry = $null; Audit = $null; ManualReason = $Reason
        }
    }

    # First pass: union of required audit directions per subcategory across ALL open
    # AuditPolicy rules. win_audit_policy_system (Ansible) sets ABSOLUTE per-subcategory
    # state, so paired Success/Failure rules for one subcategory must combine into a
    # single action. The local auditpol write only ever enables (Invoke-AuditPolSet).
    $auditDirections = @{}   # subcategory -> HashSet of 'success'/'failure'
    $auditStigIds    = @{}   # subcategory -> List of StigIds the merged action covers
    foreach ($rule in $FailedRule) {
        $stig = [string](Get-WoscapObjectProperty $rule 'StigId' '')
        $desc = if ($ContentPack.ContainsKey($stig)) { $ContentPack[$stig] } else { $null }
        if ($desc -is [hashtable] -and $desc.ContainsKey('Type') -and [string]$desc.Type -eq 'AuditPolicy' `
                -and $desc.ContainsKey('Subcategory') -and $desc.ContainsKey('Expected')) {
            $sub = [string]$desc.Subcategory
            if (-not $auditDirections.ContainsKey($sub)) {
                $auditDirections[$sub] = [System.Collections.Generic.HashSet[string]]::new()
                $auditStigIds[$sub]    = [System.Collections.Generic.List[string]]::new()
            }
            [void]$auditDirections[$sub].Add(([string]$desc.Expected).ToLowerInvariant())
            $auditStigIds[$sub].Add($stig)
        }
    }

    $actions      = [System.Collections.Generic.List[object]]::new()
    $auditEmitted = @{}   # subcategory -> $true once its single action has been added

    foreach ($rule in $FailedRule) {
        $stig  = [string](Get-WoscapObjectProperty $rule 'StigId' '')
        $title = [string](Get-WoscapObjectProperty $rule 'Title' '')
        $desc  = if ($ContentPack.ContainsKey($stig)) { $ContentPack[$stig] } else { $null }
        $checkType = if ($desc -is [hashtable] -and $desc.ContainsKey('Type')) { [string]$desc.Type } else { '' }

        switch ($checkType) {
            'Registry' {
                if (-not ($desc.ContainsKey('Path') -and $desc.ContainsKey('Name') -and $desc.ContainsKey('Expected'))) {
                    $actions.Add((& $newManual $stig $title 'Registry' 'Registry descriptor is incomplete (missing Path, Name, or Expected).'))
                    break
                }
                # Automate only when writing Expected provably makes this descriptor pass (#23).
                $op = if ($desc.ContainsKey('Operator')) { [string]$desc.Operator } else { '' }
                if ([string]::IsNullOrEmpty($op)) {
                    $actions.Add((& $newManual $stig $title 'Registry' 'Registry descriptor declares no Operator, so no write can be shown to satisfy it.'))
                    break
                }
                if ($op -notin @('eq', 'ge', 'le')) {
                    $actions.Add((& $newManual $stig $title 'Registry' "Registry operator '$op' has no single safe value to write."))
                    break
                }
                $exp = $desc.Expected
                $isInteger = $exp -is [int] -or $exp -is [long] -or $exp -is [uint32]
                # REG_DWORD reads back as Int32, so only 0..Int32.MaxValue round-trips unchanged.
                $kind = if ($isInteger -and [long]$exp -ge 0 -and [long]$exp -le [int]::MaxValue) { 'dword' }
                        elseif ($op -eq 'eq' -and $exp -is [string]) { 'string' }
                        else { $null }
                if ($null -eq $kind) {
                    $typeName = if ($null -eq $exp) { 'null' } else { $exp.GetType().Name }
                    $actions.Add((& $newManual $stig $title 'Registry' "Registry operator '$op' with Expected '$exp' ($typeName) has no value that is safe to write."))
                    break
                }
                $actions.Add([pscustomobject]@{
                    StigId = $stig; StigIds = @($stig); Title = $title; Type = 'Registry'; CheckType = 'Registry'
                    Automatable = $true
                    Registry = @{ Path = [string]$desc.Path; Name = [string]$desc.Name; Data = $desc.Expected; Kind = $kind }
                    Audit = $null; ManualReason = $null
                })
            }
            'AuditPolicy' {
                if (-not ($desc.ContainsKey('Subcategory') -and $desc.ContainsKey('Expected'))) {
                    $actions.Add((& $newManual $stig $title 'AuditPolicy' 'AuditPolicy descriptor is incomplete (missing Subcategory or Expected).'))
                    break
                }
                $sub = [string]$desc.Subcategory
                if ($auditEmitted.ContainsKey($sub)) { break }
                $auditEmitted[$sub] = $true
                $dirsSet = $auditDirections[$sub]
                $directions = @()
                if ($dirsSet.Contains('success')) { $directions += 'success' }
                if ($dirsSet.Contains('failure')) { $directions += 'failure' }
                $actions.Add([pscustomobject]@{
                    StigId = $stig; StigIds = @($auditStigIds[$sub]); Title = $title; Type = 'AuditPolicy'; CheckType = 'AuditPolicy'
                    Automatable = $true
                    Registry = $null
                    Audit = @{ Subcategory = $sub; Directions = $directions }
                    ManualReason = $null
                })
            }
            default {
                $reason = if ([string]::IsNullOrEmpty($checkType)) {
                    'No usable check descriptor is authored for this rule.'
                } else {
                    "CheckType '$checkType' has no automated remediation."
                }
                $actions.Add((& $newManual $stig $title $checkType $reason))
            }
        }
    }

    $actions.ToArray()
}

function Get-WoscapRemediationPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $FailedRule,
        [Parameter(Mandatory)] [hashtable] $ContentPack
    )

    $newManual = {
        param($StigId, $Title, $CheckType, $Reason)
        [pscustomobject]@{
            StigId = $StigId; Title = $Title; Type = 'Manual'; CheckType = $CheckType
            Automatable = $false; Registry = $null; Audit = $null; ManualReason = $Reason
        }
    }

    # First pass: union of required audit directions per subcategory across ALL open
    # AuditPolicy rules. auditpol / win_audit_policy_system set ABSOLUTE per-subcategory
    # state, so a Success-only rule must not turn Failure auditing off, and paired
    # Success/Failure rules for one subcategory must combine into a single action.
    $auditDirections = @{}   # subcategory -> HashSet of 'success'/'failure'
    foreach ($rule in $FailedRule) {
        $stig = [string](Get-WoscapObjectProperty $rule 'StigId' '')
        $desc = if ($ContentPack.ContainsKey($stig)) { $ContentPack[$stig] } else { $null }
        if ($desc -is [hashtable] -and $desc.ContainsKey('Type') -and [string]$desc.Type -eq 'AuditPolicy' `
                -and $desc.ContainsKey('Subcategory') -and $desc.ContainsKey('Expected')) {
            $sub = [string]$desc.Subcategory
            if (-not $auditDirections.ContainsKey($sub)) {
                $auditDirections[$sub] = [System.Collections.Generic.HashSet[string]]::new()
            }
            [void]$auditDirections[$sub].Add(([string]$desc.Expected).ToLowerInvariant())
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
                $kind = if ($desc.Expected -is [int] -or $desc.Expected -is [long] -or $desc.Expected -is [uint32]) { 'dword' } else { 'string' }
                $actions.Add([pscustomobject]@{
                    StigId = $stig; Title = $title; Type = 'Registry'; CheckType = 'Registry'
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
                    StigId = $stig; Title = $title; Type = 'AuditPolicy'; CheckType = 'AuditPolicy'
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

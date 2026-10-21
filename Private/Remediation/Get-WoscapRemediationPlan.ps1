function Get-WoscapRemediationPlan {
    <#
    .SYNOPSIS
        Classifies failed rules into automatic fixes and Manual items. Pure: reads and writes nothing.
    .DESCRIPTION
        The single source of remediation truth for Invoke-WoscapRemediation, the
        Ansible export and the GUI.

        A Registry rule is automatic only when writing one value provably makes it
        pass (#23, #29). An All composite whose every child is such a Registry leaf
        is one automatic fix with one write per leaf, in order (#36). A child's
        Applicability does not block this: every leaf is written unconditionally.
        Any other composite stays Manual.

        AuditPolicy rules for one subcategory merge into a single enable-only action.
        A rule whose descriptor sets Remediate = $false is always Manual.
    .PARAMETER FailedRule
        Open findings; each needs StigId and Title.
    .PARAMETER ContentPack
        The loaded content pack, keyed by StigId.
    .OUTPUTS
        One action per rule (one per subcategory for merged audit rules) with StigId,
        StigIds, Title, Type (Registry, AuditPolicy or Manual), CheckType, Automatable,
        Writes (ordered @{ Path; Name; Data; Kind }), Registry (the write when there is
        exactly one, else $null), Audit and ManualReason.
    .EXAMPLE
        Get-WoscapRemediationPlan -FailedRule $open -ContentPack (Import-ContentPack -Path .\Content\AcrobatReader)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $FailedRule,
        [Parameter(Mandatory)] [hashtable] $ContentPack
    )

    $newManual = {
        param($StigId, $Title, $CheckType, $Reason)
        [pscustomobject]@{
            StigId = $StigId; StigIds = @($StigId); Title = $Title; Type = 'Manual'; CheckType = $CheckType
            Automatable = $false; Registry = $null; Writes = @(); Audit = $null; ManualReason = $Reason
        }
    }

    # A pack may opt a rule out (Remediate = $false), e.g. when it is NA on hosts woscap cannot
    # identify. Anything but a literal $true counts as opted out, so a typo never enables a write.
    $isOptedOut = {
        param($d)
        $d -is [hashtable] -and $d.ContainsKey('Remediate') -and -not ($d.Remediate -is [bool] -and $d.Remediate)
    }

    # One Registry leaf: @{ Write } when writing Data as Kind provably makes it pass (#23),
    # else @{ Reason } naming what blocked it.
    $planLeaf = {
        param($desc)
        if (-not ($desc.ContainsKey('Path') -and $desc.ContainsKey('Name') -and $desc.ContainsKey('Expected'))) {
            return @{ Reason = 'Registry descriptor is incomplete (missing Path, Name, or Expected).' }
        }
        $path = [string]$desc.Path
        if ($path -match '^(HKCU:|(Microsoft\.PowerShell\.Core\\)?Registry::HKEY_CURRENT_USER)') {
            return @{ Reason = "Registry path is under HKCU; an elevated fix would write the operator's own hive, not the audited user's." }
        }
        $op = [string]$desc['Operator']
        # The check fails any kind outside the required ones (#29), so a
        # kind this planner cannot write is never automated.
        if ($op) {
            $required = Get-WoscapRequiredRegKind -Descriptor $desc
            if ($required.Error) {
                return @{ Reason = "Registry descriptor's value kind is invalid: $($required.Error)." }
            }
            if ($required.Kinds -ne '*' -and @(@($required.Kinds) | Where-Object { $_ -in @('DWord', 'String') }).Count -eq 0) {
                return @{ Reason = "Registry operator '$op' requires a $(@($required.Kinds) -join ' or ') value, which remediation cannot write (it writes only REG_DWORD and REG_SZ)." }
            }
        }
        if ($op -notin @('eq', 'ge', 'le')) {
            $reason = if ($op) { "Registry operator '$op' has no single safe value to write." }
                      else { 'Registry descriptor declares no Operator, so no write can be shown to satisfy it.' }
            return @{ Reason = $reason }
        }
        $exp = $desc.Expected
        # REG_DWORD reads back as Int32, so only Int32 values round-trip unchanged.
        # [decimal] holds every integer type, so a UInt64 cannot overflow the range test.
        $isInt32 = (Test-WoscapIntegerValue $exp) -and
                   [decimal]$exp -ge [int]::MinValue -and [decimal]$exp -le [int]::MaxValue
        # A declared Kind keeps the value's registry type (e.g. a REG_SZ holding a number).
        $declared = [string]$desc['Kind']
        if (-not $declared) { $declared = if ($isInt32) { 'dword' } elseif ($exp -is [string]) { 'string' } else { '' } }
        $kind = $null
        $data = $exp
        switch ($declared) {
            'dword'  { if ($isInt32) { $kind = 'dword' } }
            'string' {
                # ge/le compare numerically, so a string threshold is not trusted.
                if ($isInt32) { $kind = 'string'; $data = [string]$exp }
                elseif ($op -eq 'eq' -and $exp -is [string]) { $kind = 'string' }
            }
        }
        if ($null -eq $kind) {
            $typeName = if ($null -eq $exp) { 'null' } else { $exp.GetType().Name }
            $kindNote = if ($declared) { " as declared Kind '$declared'" } else { '' }
            return @{ Reason = "Registry operator '$op' with Expected '$exp' ($typeName) has no value that is safe to write$kindNote." }
        }
        if ($kind -eq 'dword') { $data = [int]$data }   # e.g. a [byte] Expected is written as Int32
        $writtenKind = if ($kind -eq 'dword') { 'DWord' } else { 'String' }
        if (@($required.Kinds) -notcontains $writtenKind) {
            return @{ Reason = "Registry operator '$op' requires a $(@($required.Kinds) -join ' or ') value, but the only safe write is $writtenKind." }
        }
        @{ Write = @{ Path = $path; Name = [string]$desc.Name; Data = $data; Kind = $kind } }
    }

    # Writes holds every write in order. Registry mirrors a lone write and is $null for
    # several, so a consumer that reads only Registry fails instead of applying one.
    $newRegistryAction = {
        param($StigId, $Title, $CheckType, $Writes)
        [pscustomobject]@{
            StigId = $StigId; StigIds = @($StigId); Title = $Title; Type = 'Registry'; CheckType = $CheckType
            Automatable = $true
            Registry = if (@($Writes).Count -eq 1) { $Writes[0] } else { $null }
            Writes = @($Writes); Audit = $null; ManualReason = $null
        }
    }

    # First pass: union of required audit directions per subcategory across ALL open
    # AuditPolicy rules, so paired Success/Failure rules for one subcategory combine into
    # a single action. Both renderers (Invoke-AuditPolSet, the Ansible task) only enable.
    $auditDirections = @{}   # subcategory -> HashSet of 'success'/'failure'
    $auditStigIds    = @{}   # subcategory -> List of StigIds the merged action covers
    foreach ($rule in $FailedRule) {
        $stig = [string](Get-WoscapObjectProperty $rule 'StigId' '')
        $desc = if ($ContentPack.ContainsKey($stig)) { $ContentPack[$stig] } else { $null }
        if ($desc -is [hashtable] -and -not (& $isOptedOut $desc) -and $desc.ContainsKey('Type') -and [string]$desc.Type -eq 'AuditPolicy' `
                -and $desc.ContainsKey('Subcategory') -and $desc.ContainsKey('Expected') `
                -and @('success', 'failure') -contains ([string]$desc.Expected).ToLowerInvariant()) {
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

        if (& $isOptedOut $desc) {
            $why = if ($desc.ContainsKey('RemediateReason') -and $desc.RemediateReason) { ": $($desc.RemediateReason)" } else { '.' }
            $actions.Add((& $newManual $stig $title $checkType "The content pack opts this rule out of automatic remediation$why"))
            continue
        }

        switch ($checkType) {
            'Registry' {
                $leaf = & $planLeaf $desc
                if ($leaf.ContainsKey('Reason')) {
                    $actions.Add((& $newManual $stig $title 'Registry' $leaf.Reason))
                    break
                }
                $actions.Add((& $newRegistryAction $stig $title 'Registry' @($leaf.Write)))
            }
            'All' {
                # Every leaf is written unconditionally; a child's Applicability only gates the check (#36).
                $children = @(if ($desc.ContainsKey('Checks')) { $desc.Checks })
                $writes = @(foreach ($child in $children) {
                    if (-not ($child -is [hashtable] -and [string]$child['Type'] -eq 'Registry') -or (& $isOptedOut $child)) { break }
                    $leaf = & $planLeaf $child
                    if ($leaf.ContainsKey('Reason')) { break }
                    $leaf.Write
                })
                if ($children.Count -gt 0 -and $writes.Count -eq $children.Count) {
                    $actions.Add((& $newRegistryAction $stig $title 'All' $writes))
                } else {
                    $actions.Add((& $newManual $stig $title 'All' "CheckType 'All' has no automated remediation."))
                }
            }
            'AuditPolicy' {
                if (-not ($desc.ContainsKey('Subcategory') -and $desc.ContainsKey('Expected'))) {
                    $actions.Add((& $newManual $stig $title 'AuditPolicy' 'AuditPolicy descriptor is incomplete (missing Subcategory or Expected).'))
                    break
                }
                if (@('success', 'failure') -notcontains ([string]$desc.Expected).ToLowerInvariant()) {
                    $actions.Add((& $newManual $stig $title 'AuditPolicy' "AuditPolicy Expected '$($desc.Expected)' is not Success or Failure, so there is no direction to enable."))
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
                    Registry = $null; Writes = @()
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

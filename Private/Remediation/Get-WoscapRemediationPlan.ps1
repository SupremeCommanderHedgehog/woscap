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

    # A pack may opt a rule out (Remediate = $false), e.g. when it is NA on hosts woscap cannot
    # identify. Anything but a literal $true counts as opted out, so a typo never enables a write.
    $isOptedOut = {
        param($d)
        $d -is [hashtable] -and $d.ContainsKey('Remediate') -and -not ($d.Remediate -is [bool] -and $d.Remediate)
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
                if (-not ($desc.ContainsKey('Path') -and $desc.ContainsKey('Name') -and $desc.ContainsKey('Expected'))) {
                    $actions.Add((& $newManual $stig $title 'Registry' 'Registry descriptor is incomplete (missing Path, Name, or Expected).'))
                    break
                }
                # Automate only when writing Data as Kind provably makes this descriptor pass (#23).
                $path = [string]$desc.Path
                if ($path -match '^(HKCU:|(Microsoft\.PowerShell\.Core\\)?Registry::HKEY_CURRENT_USER)') {
                    $actions.Add((& $newManual $stig $title 'Registry' "Registry path is under HKCU; an elevated fix would write the operator's own hive, not the audited user's."))
                    break
                }
                $op = [string]$desc['Operator']
                if ($op -notin @('eq', 'ge', 'le')) {
                    $reason = if ($op) { "Registry operator '$op' has no single safe value to write." }
                              else { 'Registry descriptor declares no Operator, so no write can be shown to satisfy it.' }
                    $actions.Add((& $newManual $stig $title 'Registry' $reason))
                    break
                }
                $exp = $desc.Expected
                # REG_DWORD reads back as Int32, so only Int32 values round-trip unchanged.
                $isInt32 = ($exp -is [int] -or $exp -is [long] -or $exp -is [uint32]) -and
                           [long]$exp -ge [int]::MinValue -and [long]$exp -le [int]::MaxValue
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
                    $actions.Add((& $newManual $stig $title 'Registry' "Registry operator '$op' with Expected '$exp' ($typeName) has no value that is safe to write$kindNote."))
                    break
                }
                $actions.Add([pscustomobject]@{
                    StigId = $stig; StigIds = @($stig); Title = $title; Type = 'Registry'; CheckType = 'Registry'
                    Automatable = $true
                    Registry = @{ Path = $path; Name = [string]$desc.Name; Data = $data; Kind = $kind }
                    Audit = $null; ManualReason = $null
                })
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

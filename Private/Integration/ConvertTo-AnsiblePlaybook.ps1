function ConvertTo-AnsiblePlaybook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $FailedRule,
        [Parameter(Mandatory)] [hashtable] $ContentPack
    )

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('- name: woscap STIG remediation')
    [void]$sb.AppendLine('  hosts: all')
    [void]$sb.AppendLine('  tasks:')

    # win_audit_policy_system sets ABSOLUTE state per subcategory: emitting one task
    # per rule would let a Success-only rule turn OFF Failure auditing (and paired
    # Success/Failure STIG rules for the same subcategory would overwrite each other).
    # So gather the required directions across every open AuditPolicy rule per
    # subcategory and emit ONE task per subcategory (at its first-encountered slot),
    # while all other check types stay per-rule.
    $auditDirections = @{}   # subcategory -> HashSet of 'success'/'failure'
    $auditEmitted    = @{}   # subcategory -> $true once its task has been written
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

    foreach ($rule in $FailedRule) {
        $stig = [string](Get-WoscapObjectProperty $rule 'StigId' '')
        $title = [string](Get-WoscapObjectProperty $rule 'Title' '')
        $desc = if ($ContentPack.ContainsKey($stig)) { $ContentPack[$stig] } else { $null }
        # A conformant descriptor is a hashtable with a Type key. Anything else
        # (a bare scriptblock/scalar merged from checks.overrides, or a missing
        # descriptor) falls through to the fail-visible "# manual:" line.
        $type = if ($desc -is [hashtable] -and $desc.ContainsKey('Type')) { [string]$desc.Type } else { '' }

        switch ($type) {
            'Registry' {
                if (-not ($desc.ContainsKey('Path') -and $desc.ContainsKey('Name') -and $desc.ContainsKey('Expected'))) {
                    [void]$sb.AppendLine("    # manual: $stig - $title (Registry descriptor missing Path/Name/Expected)")
                    break
                }
                $regType = if ($desc.Expected -is [int]) { 'dword' } else { 'string' }
                [void]$sb.AppendLine("    - name: $stig - $title")
                [void]$sb.AppendLine('      win_regedit:')
                [void]$sb.AppendLine("        path: $($desc.Path)")
                [void]$sb.AppendLine("        name: $($desc.Name)")
                [void]$sb.AppendLine("        data: $($desc.Expected)")
                [void]$sb.AppendLine("        type: $regType")
            }
            'AuditPolicy' {
                if (-not ($desc.ContainsKey('Subcategory') -and $desc.ContainsKey('Expected'))) {
                    [void]$sb.AppendLine("    # manual: $stig - $title (AuditPolicy descriptor missing Subcategory/Expected)")
                    break
                }
                $sub = [string]$desc.Subcategory
                # Emit one combined task per subcategory, at the first open rule that
                # references it; later rules for the same subcategory are folded in.
                if ($auditEmitted.ContainsKey($sub)) { break }
                $auditEmitted[$sub] = $true
                $dirs = $auditDirections[$sub]
                $auditType = if ($dirs.Contains('success') -and $dirs.Contains('failure')) {
                    'success and failure'
                } elseif ($dirs.Contains('failure')) {
                    'failure'
                } else {
                    'success'
                }
                # Quote the name: an unquoted "Audit policy: <sub>" contains a ': '
                # which YAML reads as a mapping indicator, so ansible-playbook would
                # refuse to parse the playbook.
                [void]$sb.AppendLine("    - name: `"Audit policy: $sub`"")
                [void]$sb.AppendLine('      win_audit_policy_system:')
                [void]$sb.AppendLine("        subcategory: $sub")
                [void]$sb.AppendLine("        audit_type: $auditType")
            }
            default {
                [void]$sb.AppendLine("    # manual: $stig - $title (CheckType '$type' has no Ansible mapping)")
            }
        }
    }

    $sb.ToString().TrimEnd()
}

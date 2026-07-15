function ConvertTo-AnsiblePlaybook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $FailedRule,
        [Parameter(Mandatory)] [hashtable] $ContentPack
    )

    # Classification + audit aggregation live in the shared planner (one source of
    # remediation truth). This function only RENDERS the plan as an Ansible playbook.
    $plan = Get-WoscapRemediationPlan -FailedRule $FailedRule -ContentPack $ContentPack

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('---')
    [void]$sb.AppendLine('- name: woscap STIG remediation')
    [void]$sb.AppendLine('  hosts: all')
    [void]$sb.AppendLine('  tasks:')

    foreach ($action in $plan) {
        switch ($action.Type) {
            'Registry' {
                $reg = $action.Registry
                [void]$sb.AppendLine("    - name: $($action.StigId) - $($action.Title)")
                [void]$sb.AppendLine('      win_regedit:')
                [void]$sb.AppendLine("        path: $($reg.Path)")
                [void]$sb.AppendLine("        name: $($reg.Name)")
                [void]$sb.AppendLine("        data: $($reg.Data)")
                [void]$sb.AppendLine("        type: $($reg.Kind)")
            }
            'AuditPolicy' {
                $dirs = $action.Audit.Directions
                $auditType = if (($dirs -contains 'success') -and ($dirs -contains 'failure')) {
                    'success and failure'
                } elseif ($dirs -contains 'failure') {
                    'failure'
                } else {
                    'success'
                }
                $sub = $action.Audit.Subcategory
                # Quote the name: an unquoted "Audit policy: <sub>" embeds a ': ' which YAML
                # reads as a mapping indicator, so ansible-playbook would refuse to parse it.
                [void]$sb.AppendLine("    - name: `"Audit policy: $sub`"")
                [void]$sb.AppendLine('      win_audit_policy_system:')
                [void]$sb.AppendLine("        subcategory: $sub")
                [void]$sb.AppendLine("        audit_type: $auditType")
            }
            'Manual' {
                # Ansible-specific wording, reproduced from the action's CheckType so the
                # emitter output stays byte-identical to the pre-refactor behavior. This is
                # intentionally NOT action.ManualReason (whose wording is tool-agnostic and
                # differs) — substituting it here would break the golden-file test.
                $reason = if ($action.CheckType -eq 'Registry') {
                    'Registry descriptor missing Path/Name/Expected'
                } elseif ($action.CheckType -eq 'AuditPolicy') {
                    'AuditPolicy descriptor missing Subcategory/Expected'
                } else {
                    "CheckType '$($action.CheckType)' has no Ansible mapping"
                }
                [void]$sb.AppendLine("    # manual: $($action.StigId) - $($action.Title) ($reason)")
            }
        }
    }

    $sb.ToString().TrimEnd()
}

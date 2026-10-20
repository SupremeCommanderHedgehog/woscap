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
                # Registry uses the planner's reason, which names the operator that blocked the write.
                # Other types keep their Ansible-specific wording (pinned by the golden file).
                $reason = if ($action.CheckType -eq 'Registry') {
                    # A newline would end the YAML comment early.
                    [string]$action.ManualReason -replace '[\r\n]+', ' '
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

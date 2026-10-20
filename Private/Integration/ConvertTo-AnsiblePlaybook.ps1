function ConvertTo-AnsiblePlaybook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $FailedRule,
        [Parameter(Mandatory)] [hashtable] $ContentPack
    )

    # Classification + audit aggregation live in the shared planner (one source of
    # remediation truth). This function only RENDERS the plan as an Ansible playbook.
    $plan = Get-WoscapRemediationPlan -FailedRule $FailedRule -ContentPack $ContentPack

    $auditScript = (Get-WoscapAnsibleAuditScript).TrimEnd()
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
                # Enable-only win_powershell task (#21): win_audit_policy_system sets
                # absolute state and would disable already-compliant directions.
                $sub = [string]$action.Audit.Subcategory
                [void]$sb.AppendLine("    - name: $(ConvertTo-WoscapYamlString "Audit policy: $sub")")
                [void]$sb.AppendLine('      ansible.windows.win_powershell:')
                [void]$sb.AppendLine('        parameters:')
                [void]$sb.AppendLine("          Subcategory: $(ConvertTo-WoscapYamlString $sub)")
                [void]$sb.AppendLine('          Directions:')
                foreach ($dir in $action.Audit.Directions) {
                    [void]$sb.AppendLine("            - $dir")
                }
                [void]$sb.AppendLine('        script: |')
                foreach ($line in ($auditScript -split '\r?\n')) {
                    [void]$sb.AppendLine($(if ($line) { "          $line" } else { '' }))
                }
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

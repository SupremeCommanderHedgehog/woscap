function ConvertTo-AnsiblePlaybook {
    <#
    .SYNOPSIS
        Renders the remediation plan for failed rules as an Ansible playbook (YAML text).
    .DESCRIPTION
        Classification comes from Get-WoscapRemediationPlan. Each registry write is one
        quoted, idempotent win_regedit task; a multi-write fix gets one task per write, in
        order, named "(write i of n)". Audit fixes are enable-only win_powershell tasks, and
        every Manual rule is a "# manual:" comment with its reason.
    .PARAMETER FailedRule
        Open findings; each needs StigId and Title.
    .PARAMETER ContentPack
        The loaded content pack, keyed by StigId.
    .OUTPUTS
        [string] The playbook.
    .EXAMPLE
        ConvertTo-AnsiblePlaybook -FailedRule $open -ContentPack $pack | Set-Content .\fix.yml
    #>
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
                # One task per write; a multi-write fix numbers its tasks so each name is unique.
                $writes = @($action.Writes)
                for ($i = 0; $i -lt $writes.Count; $i++) {
                    $reg = $writes[$i]
                    $name = "$($action.StigId) - $($action.Title)"
                    if ($writes.Count -gt 1) { $name += " (write $($i + 1) of $($writes.Count))" }
                    # Quote every scalar so YAML cannot re-type ('yes', '10') or misparse it.
                    # A dword stays a bare integer: the planner guarantees it is an Int32.
                    $data = if ($reg.Kind -eq 'dword') { [string][int]$reg.Data } else { ConvertTo-WoscapYamlString ([string]$reg.Data) }
                    [void]$sb.AppendLine("    - name: $(ConvertTo-WoscapYamlString $name)")
                    [void]$sb.AppendLine('      win_regedit:')
                    [void]$sb.AppendLine("        path: $(ConvertTo-WoscapYamlString ([string]$reg.Path))")
                    [void]$sb.AppendLine("        name: $(ConvertTo-WoscapYamlString ([string]$reg.Name))")
                    [void]$sb.AppendLine("        data: $data")
                    [void]$sb.AppendLine("        type: $(ConvertTo-WoscapYamlString ([string]$reg.Kind))")
                }
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
                # Registry/AuditPolicy use the planner's reason (it names what blocked the fix).
                # Other types keep their Ansible-specific wording (pinned by the golden file).
                $reason = if ($action.CheckType -in @('Registry', 'AuditPolicy')) {
                    [string]$action.ManualReason
                } else {
                    "CheckType '$($action.CheckType)' has no Ansible mapping"
                }
                # Line breaks (incl. NEL, U+2028/9) would end the comment early; other
                # controls are not allowed in YAML at all.
                $comment = "$($action.StigId) - $($action.Title) ($reason)" -replace '[\p{Cc}\p{Cf}\p{Cs}\p{Cn}\p{Zl}\p{Zp}]+', ' '
                [void]$sb.AppendLine("    # manual: $comment")
            }
        }
    }

    $sb.ToString().TrimEnd()
}

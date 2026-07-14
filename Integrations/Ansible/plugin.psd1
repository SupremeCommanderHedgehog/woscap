@{
    Name           = 'Ansible'
    Version        = '1.0.0'
    Description    = 'Inventory targets; STIG remediation-as-code playbooks; facts export.'
    Capabilities   = @('Get-Targets', 'New-Remediation', 'Export-Findings')
    Implementation = 'implementation.ps1'
}

@{
    Name           = 'Ansible'
    Version        = '1.0.0'
    Description    = 'Inventory targets; STIG remediation-as-code playbooks; facts export.'
    Capabilities   = @('Get-Targets', 'New-Remediation', 'Export-Findings')
    Implementation = 'implementation.ps1'
    ConfigOptions  = @(
        @{ Name = 'Group'; Type = 'Text'; Hooks = @('Get-Targets'); Help = 'Inventory group to read; blank reads all hosts.' }
        @{ Name = 'Benchmark'; Type = 'Text'; Hooks = @('New-Remediation'); Default = 'Windows11'; Help = 'Bundled content benchmark folder.' }
        @{ Name = 'ContentPath'; Type = 'Path'; PathKind = 'Folder'; Hooks = @('New-Remediation'); Help = 'Content pack path; overrides Benchmark.' }
        @{ Name = 'FactsPath'; Type = 'Path'; PathKind = 'SaveFile'; Hooks = @('Export-Findings'); Help = 'Where to write the facts JSON; defaults to a temp file.' }
    )
}

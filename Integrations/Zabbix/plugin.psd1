@{
    Name           = 'Zabbix'
    Version        = '1.0.0'
    Description    = 'Push compliance metrics via the Zabbix sender protocol; pull hosts from inventory.'
    Capabilities   = @('Export-Findings', 'Get-Targets')
    Implementation = 'implementation.ps1'
}

@{
    Name           = 'Zabbix'
    Version        = '1.0.0'
    Description    = 'Push compliance metrics via the Zabbix sender protocol; pull hosts from inventory.'
    Capabilities   = @('Export-Findings', 'Get-Targets')
    Implementation = 'implementation.ps1'
    ConfigOptions  = @(
        @{ Name = 'Server'; Type = 'Text'; Hooks = @('Export-Findings'); Required = $true; Help = 'Zabbix server or proxy for the sender protocol.' }
        @{ Name = 'Port'; Type = 'Number'; Hooks = @('Export-Findings'); Default = 10051; Help = 'Zabbix trapper port.' }
        @{ Name = 'ApiUrl'; Type = 'Text'; Hooks = @('Get-Targets'); Required = $true; Help = 'Zabbix API URL (api_jsonrpc.php).' }
        @{ Name = 'Token'; Type = 'Secret'; Hooks = @('Get-Targets'); Required = $true; Help = 'Zabbix API token (passed as a string).' }
    )
}

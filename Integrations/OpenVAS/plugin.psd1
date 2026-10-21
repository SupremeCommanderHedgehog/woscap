@{
    Name           = 'OpenVAS'
    Version        = '1.0.0'
    Description    = 'Ingest Greenbone/OpenVAS report XML; correlate CVE/CCE findings with STIG results.'
    Capabilities   = @('Import-Findings', 'Invoke-ExternalScan')
    Implementation = 'implementation.ps1'
    ConfigOptions  = @(
        @{ Name = 'HostMap'; Type = 'Table'; Hooks = @('Import-Findings'); Help = 'Optional map of report host names/IPs to scanned host names for correlation.' }
        @{ Name = 'ResolveDns'; Type = 'Bool'; Hooks = @('Import-Findings'); Default = $false; Help = 'Resolve report hosts via DNS when correlating with scan results.' }
        @{ Name = 'Server'; Type = 'Text'; Hooks = @('Invoke-ExternalScan'); Required = $true; Help = 'gvmd server name or address.' }
        @{ Name = 'Credential'; Type = 'Credential'; Hooks = @('Invoke-ExternalScan'); Required = $true; Help = 'gvmd login (user and password).' }
        @{ Name = 'Targets'; Type = 'List'; Hooks = @('Invoke-ExternalScan'); Required = $true; Help = 'Hosts or CIDRs to scan, one per line.' }
        @{ Name = 'ScanConfigId'; Type = 'Text'; Hooks = @('Invoke-ExternalScan'); Required = $true; Help = 'UUID of the scan config.' }
        @{ Name = 'ScannerId'; Type = 'Text'; Hooks = @('Invoke-ExternalScan'); Required = $true; Help = 'UUID of the scanner.' }
        @{ Name = 'Port'; Type = 'Number'; Hooks = @('Invoke-ExternalScan'); Help = 'gvmd port.' }
        @{ Name = 'PollSeconds'; Type = 'Number'; Hooks = @('Invoke-ExternalScan'); Help = 'Seconds between task status polls.' }
        @{ Name = 'TimeoutMinutes'; Type = 'Number'; Hooks = @('Invoke-ExternalScan'); Help = 'Overall scan timeout in minutes.' }
        @{ Name = 'RequestTimeoutMs'; Type = 'Number'; Hooks = @('Invoke-ExternalScan'); Help = 'Per-request timeout in milliseconds.' }
        @{ Name = 'ReportTimeoutMs'; Type = 'Number'; Hooks = @('Invoke-ExternalScan'); Help = 'Report download timeout in milliseconds.' }
        @{ Name = 'SshCredentialPort'; Type = 'Number'; Hooks = @('Invoke-ExternalScan'); Help = 'SSH port used with SshCredentialId.' }
        @{ Name = 'PortListId'; Type = 'Text'; Hooks = @('Invoke-ExternalScan'); Help = 'UUID of an existing port list.' }
        @{ Name = 'PortRange'; Type = 'Text'; Hooks = @('Invoke-ExternalScan'); Help = 'Port range, used when no PortListId is given.' }
        @{ Name = 'SmbCredentialId'; Type = 'Text'; Hooks = @('Invoke-ExternalScan'); Help = 'UUID of an SMB credential stored in gvmd.' }
        @{ Name = 'SshCredentialId'; Type = 'Text'; Hooks = @('Invoke-ExternalScan'); Help = 'UUID of an SSH credential stored in gvmd.' }
        @{ Name = 'AliveTest'; Type = 'Text'; Hooks = @('Invoke-ExternalScan'); Help = 'Host alive test name.' }
        @{ Name = 'SkipCertificateCheck'; Type = 'Bool'; Hooks = @('Invoke-ExternalScan'); Help = 'Skip TLS certificate validation (self-signed gvmd).' }
    )
}

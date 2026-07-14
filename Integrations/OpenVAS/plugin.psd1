@{
    Name           = 'OpenVAS'
    Version        = '1.0.0'
    Description    = 'Ingest Greenbone/OpenVAS report XML; correlate CVE/CCE findings with STIG results.'
    Capabilities   = @('Import-Findings', 'Invoke-ExternalScan')
    Implementation = 'implementation.ps1'
}

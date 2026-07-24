@{
    'Import-Findings' = {
        param([string] $Path, $Config)
        ConvertFrom-OpenVasReport -Path $Path
    }
    'Invoke-ExternalScan' = {
        param($Config)
        if (-not $Config) { $Config = @{} }

        foreach ($k in 'Server', 'Credential', 'Targets', 'ScanConfigId', 'ScannerId') {
            if (-not $Config.ContainsKey($k) -or -not $Config[$k]) {
                Write-Warning "woscap: OpenVAS Invoke-ExternalScan requires -Config '$k'."
                return @()
            }
        }

        if ($Config['Credential'] -isnot [pscredential]) {
            Write-Warning "woscap: OpenVAS Invoke-ExternalScan -Config 'Credential' must be a PSCredential."
            return @()
        }

        $params = @{
            Server       = [string]$Config['Server']
            Credential   = $Config['Credential']
            Targets      = @($Config['Targets'])
            ScanConfigId = [string]$Config['ScanConfigId']
            ScannerId    = [string]$Config['ScannerId']
        }
        foreach ($numKey in 'Port', 'PollSeconds', 'TimeoutMinutes', 'RequestTimeoutMs', 'ReportTimeoutMs', 'SshCredentialPort') {
            if ($Config.ContainsKey($numKey)) {
                $parsed = 0
                if ([int]::TryParse([string]$Config[$numKey], [ref]$parsed)) {
                    $params[$numKey] = $parsed
                } else {
                    Write-Warning "woscap: OpenVAS Invoke-ExternalScan ignoring non-numeric -Config '$numKey'."
                }
            }
        }
        foreach ($strKey in 'PortListId', 'PortRange', 'SmbCredentialId', 'SshCredentialId', 'AliveTest') {
            if ($Config.ContainsKey($strKey) -and $Config[$strKey]) {
                $params[$strKey] = [string]$Config[$strKey]
            }
        }
        if ($Config.ContainsKey('SkipCertificateCheck')) {
            $rawSkip = $Config['SkipCertificateCheck']
            if ($rawSkip -is [string]) { $params['SkipCertificateCheck'] = [bool]($rawSkip.Trim() -match '^(1|true|yes|on)$') }
            else                       { $params['SkipCertificateCheck'] = [bool]$rawSkip }
        }

        $report = Invoke-WoscapOpenVasScan @params
        if (-not $report) { return @() }   # orchestrator already warned
        ConvertFrom-OpenVasReport -Xml $report
    }
}

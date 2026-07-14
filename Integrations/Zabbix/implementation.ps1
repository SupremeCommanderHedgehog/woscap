@{
    'Export-Findings' = {
        param($Result, $Config)
        $server = if ($Config -and $Config.ContainsKey('Server')) { [string]$Config.Server } else { $null }
        if (-not $server) { Write-Warning 'woscap: Zabbix Export-Findings requires -Config @{ Server = ... }.'; return $false }
        $port = if ($Config.ContainsKey('Port')) { [int]$Config.Port } else { 10051 }

        $allOk = $true
        foreach ($group in ($Result | Group-Object Host)) {
            $metrics = Get-WoscapComplianceMetric -Result @($group.Group)
            $ok = Send-WoscapZabbixMetric -Server $server -Port $port -HostName $group.Name -Metric $metrics
            if (-not $ok) { $allOk = $false }
        }
        $allOk
    }
    'Get-Targets' = {
        param($Source, $Config)
        if (-not $Config -or -not $Config.ContainsKey('ApiUrl') -or -not $Config.ContainsKey('Token')) {
            Write-Warning 'woscap: Zabbix Get-Targets requires -Config @{ ApiUrl = ...; Token = ... }.'; return @()
        }
        Get-WoscapZabbixHost -ApiUrl $Config.ApiUrl -Token $Config.Token
    }
}

function Get-WoscapZabbixHost {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ApiUrl,
        [Parameter(Mandatory)] [string] $Token
    )

    $body = @{
        jsonrpc = '2.0'
        method  = 'host.get'
        params  = @{ output = @('host') }
        id      = 1
        auth    = $Token
    } | ConvertTo-Json -Depth 4

    try {
        $resp = Invoke-RestMethod -Uri $ApiUrl -Method Post -ContentType 'application/json-rpc' -Body $body
        # A JSON-RPC error reply carries an `error` object and NO `result` member, so
        # reading `$resp.result` would throw under StrictMode. Check for `error` first.
        $err = Get-WoscapObjectProperty $resp 'error'
        if ($err) {
            $msg  = Get-WoscapObjectProperty $err 'message'
            $data = Get-WoscapObjectProperty $err 'data'
            Write-Warning "woscap: Zabbix host.get error: $msg $data"
            return @()
        }
        $result = Get-WoscapObjectProperty $resp 'result'
        @($result | ForEach-Object { Get-WoscapObjectProperty $_ 'host' })
    } catch {
        Write-Warning "woscap: Zabbix host.get failed: $_"; return @()
    }
}

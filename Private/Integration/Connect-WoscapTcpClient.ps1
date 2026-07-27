function Connect-WoscapTcpClient {
    <#
        .SYNOPSIS
        Open a TCP connection to an operator-side endpoint, bounded by a timeout.

        .DESCRIPTION
        TcpClient.Connect() has no timeout, so every woscap integration connects via
        ConnectAsync().Wait($TimeoutMs). Centralized here so the connect-with-timeout
        contract (wait, verify .Connected, warn once, close the socket, return $null)
        lives in one place rather than being re-derived per integration.

        Fail-warn-only: an unreachable endpoint warns and returns $null; it never
        throws. On success the caller owns the returned client and must close it.

        .PARAMETER Label
        Endpoint name used in the warning text, e.g. 'OpenVAS GMP' / 'Zabbix trapper'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Server,
        [Parameter(Mandatory)] [int] $Port,
        [int] $TimeoutMs = 30000,
        [string] $Label = 'TCP endpoint'
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.ConnectAsync($Server, $Port)
        if (-not $connect.Wait($TimeoutMs) -or -not $client.Connected) {
            Write-Warning "woscap: $Label ${Server}:${Port} unreachable (connect timed out)."
            $client.Close(); return $null
        }
    } catch {
        # A refused/faulted connect surfaces as an AggregateException from .Wait();
        # the inner message is the useful diagnostic.
        $reason = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        Write-Warning "woscap: $Label ${Server}:${Port} unreachable: $reason"
        $client.Close(); return $null
    }
    $client
}

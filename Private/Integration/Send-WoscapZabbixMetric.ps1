function Send-WoscapZabbixMetric {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Server,
        [int] $Port = 10051,
        [Parameter(Mandatory)] [string] $HostName,
        [Parameter(Mandatory)] [hashtable] $Metric,
        [int] $TimeoutMs = 5000
    )

    $data = foreach ($key in $Metric.Keys) {
        @{ host = $HostName; key = $key; value = [string]$Metric[$key] }
    }
    $payload = @{ request = 'sender data'; data = @($data) } | ConvertTo-Json -Depth 4 -Compress
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)

    $header = [System.Collections.Generic.List[byte]]::new()
    $header.AddRange([System.Text.Encoding]::ASCII.GetBytes('ZBXD'))
    $header.Add([byte]1)
    $header.AddRange([System.BitConverter]::GetBytes([int64]$payloadBytes.Length))  # little-endian on Windows
    $frame = $header.ToArray() + $payloadBytes

    # Connect-with-timeout (and its unreachable warning) is shared with the other
    # socket integrations; $null here means it already warned.
    $client = Connect-WoscapTcpClient -Server $Server -Port $Port -TimeoutMs $TimeoutMs -Label 'Zabbix trapper'
    if (-not $client) { return $false }

    try {
        $stream = $client.GetStream()
        # Bound the reply read so a trapper (or proxy) that accepts the connection but
        # never replies can't hang the caller forever; the IOException lands in catch -> $false.
        $stream.ReadTimeout = $TimeoutMs
        $stream.Write($frame, 0, $frame.Length)
        $stream.Flush()

        # Read and parse the trapper reply. A trapper that acknowledges the frame but
        # rejected every value (info -> "failed: N" with N == total) is a silent failure.
        $respHeader = New-Object byte[] 13
        $got = 0
        while ($got -lt 13) {
            $n = $stream.Read($respHeader, $got, 13 - $got)
            if ($n -le 0) { break }
            $got += $n
        }
        if ($got -lt 13 -or [System.Text.Encoding]::ASCII.GetString($respHeader, 0, 4) -ne 'ZBXD') {
            Write-Warning "woscap: Zabbix ${Server}:${Port} returned no valid response header."; return $false
        }
        $respLen = [System.BitConverter]::ToInt64($respHeader, 5)
        # A real Zabbix info reply is well under 64 KiB; refuse an implausible length
        # so a corrupt/hostile header can't drive a huge (or negative) allocation.
        if ($respLen -lt 0 -or $respLen -gt 65536) {
            Write-Warning "woscap: Zabbix ${Server}:${Port} reply length $respLen out of range."; return $false
        }
        $respBody = New-Object byte[] $respLen
        $off = 0
        while ($off -lt $respLen) {
            $n = $stream.Read($respBody, $off, [int]($respLen - $off))
            if ($n -le 0) { break }
            $off += $n
        }
        $json = [System.Text.Encoding]::UTF8.GetString($respBody, 0, $off) | ConvertFrom-Json
        $response = Get-WoscapObjectProperty $json 'response'
        $info     = [string](Get-WoscapObjectProperty $json 'info' '')
        # "processed: N; failed: M; total: T; ..." — treat all-failed (M == T, T > 0) as failure.
        $allFailed = $false
        if ($info -match 'failed:\s*(\d+)' -and $info -match 'total:\s*(\d+)') {
            $failed = [int]([regex]::Match($info, 'failed:\s*(\d+)').Groups[1].Value)
            $total  = [int]([regex]::Match($info, 'total:\s*(\d+)').Groups[1].Value)
            $allFailed = ($total -gt 0 -and $failed -ge $total)
        }
        if ($response -eq 'success' -and -not $allFailed) {
            return $true
        }
        Write-Warning "woscap: Zabbix ${Server}:${Port} rejected metrics (response='$response', info='$info')."
        return $false
    } catch {
        Write-Warning "woscap: Zabbix send to ${Server}:${Port} failed: $_"; return $false
    } finally {
        $client.Close()
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Send-WoscapZabbixMetric' {
    It 'sends a well-formed frame and returns $true when the trapper replies success' {
        InModuleScope woscap {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
            try {
                $accept = $listener.AcceptTcpClientAsync()
                # Drive the trapper on a background runspace so the sender can read our reply.
                $ps = [powershell]::Create()
                [void]$ps.AddScript({
                    param($accept)
                    $accept.Wait(5000) | Out-Null
                    $client = $accept.Result
                    $stream = $client.GetStream()
                    $header = New-Object byte[] 13
                    $off = 0
                    while ($off -lt 13) { $off += $stream.Read($header, $off, 13 - $off) }
                    $len = [System.BitConverter]::ToInt64($header, 5)
                    $body = New-Object byte[] $len
                    $boff = 0
                    while ($boff -lt $len) { $boff += $stream.Read($body, $boff, $len - $boff) }
                    $reqJson = [System.Text.Encoding]::UTF8.GetString($body)
                    $respBody = '{"response":"success","info":"processed: 1; failed: 0; total: 1; seconds spent: 0.0"}'
                    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($respBody)
                    $reply = [System.Collections.Generic.List[byte]]::new()
                    $reply.AddRange([System.Text.Encoding]::ASCII.GetBytes('ZBXD'))
                    $reply.Add([byte]1)
                    $reply.AddRange([System.BitConverter]::GetBytes([int64]$bodyBytes.Length))
                    $reply.AddRange($bodyBytes)
                    $arr = $reply.ToArray()
                    $stream.Write($arr, 0, $arr.Length); $stream.Flush()
                    $reqJson
                }).AddArgument($accept)
                $handle = $ps.BeginInvoke()

                $ok = Send-WoscapZabbixMetric -Server '127.0.0.1' -Port $port -HostName 'SRV01' -Metric @{ 'woscap.open.cat1' = 3 }
                $ok | Should -BeTrue

                $reqJson = @($ps.EndInvoke($handle))[0]
                $ps.Dispose()
                $json = $reqJson | ConvertFrom-Json
                $json.request | Should -Be 'sender data'
                $json.data[0].host  | Should -Be 'SRV01'
                $json.data[0].key   | Should -Be 'woscap.open.cat1'
                $json.data[0].value | Should -Be '3'
            } finally { $listener.Stop() }
        }
    }
    It 'returns $false when the trapper reports all values failed' {
        InModuleScope woscap {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
            try {
                $accept = $listener.AcceptTcpClientAsync()
                $ps = [powershell]::Create()
                [void]$ps.AddScript({
                    param($accept)
                    $accept.Wait(5000) | Out-Null
                    $client = $accept.Result
                    $stream = $client.GetStream()
                    $header = New-Object byte[] 13
                    $off = 0
                    while ($off -lt 13) { $off += $stream.Read($header, $off, 13 - $off) }
                    $len = [System.BitConverter]::ToInt64($header, 5)
                    $body = New-Object byte[] $len
                    $boff = 0
                    while ($boff -lt $len) { $boff += $stream.Read($body, $boff, $len - $boff) }
                    $respBody = '{"response":"success","info":"processed: 0; failed: 1; total: 1; seconds spent: 0.0"}'
                    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($respBody)
                    $reply = [System.Collections.Generic.List[byte]]::new()
                    $reply.AddRange([System.Text.Encoding]::ASCII.GetBytes('ZBXD'))
                    $reply.Add([byte]1)
                    $reply.AddRange([System.BitConverter]::GetBytes([int64]$bodyBytes.Length))
                    $reply.AddRange($bodyBytes)
                    $arr = $reply.ToArray()
                    $stream.Write($arr, 0, $arr.Length); $stream.Flush()
                }).AddArgument($accept)
                $handle = $ps.BeginInvoke()

                $ok = Send-WoscapZabbixMetric -Server '127.0.0.1' -Port $port -HostName 'SRV01' -Metric @{ 'k' = 1 } -WarningAction SilentlyContinue
                $ok | Should -BeFalse

                $ps.EndInvoke($handle) | Out-Null
                $ps.Dispose()
            } finally { $listener.Stop() }
        }
    }
    It 'returns $false and warns when the trapper is unreachable' {
        InModuleScope woscap {
            $ok = Send-WoscapZabbixMetric -Server '127.0.0.1' -Port 1 -HostName 'H' -Metric @{ 'k' = 1 } -WarningAction SilentlyContinue
            $ok | Should -BeFalse
        }
    }
}

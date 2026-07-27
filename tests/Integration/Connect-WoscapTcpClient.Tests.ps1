BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Connect-WoscapTcpClient' {
    It 'returns a connected TcpClient when the endpoint accepts the connection' {
        InModuleScope woscap {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
            try {
                $client = Connect-WoscapTcpClient -Server '127.0.0.1' -Port $port -TimeoutMs 5000 -Label 'test endpoint'
                $client | Should -Not -BeNullOrEmpty
                $client.Connected | Should -BeTrue
                # The caller owns the socket and must be able to use it.
                $client.GetStream() | Should -Not -BeNullOrEmpty
                $client.Close()
            } finally { $listener.Stop() }
        }
    }
    It 'warns and returns $null when the connection is refused' {
        InModuleScope woscap {
            $client = Connect-WoscapTcpClient -Server '127.0.0.1' -Port 1 -TimeoutMs 1000 `
                -Label 'test endpoint' -WarningVariable w -WarningAction SilentlyContinue
            $client | Should -BeNullOrEmpty
            "$w" | Should -Match 'test endpoint 127\.0\.0\.1:1'
            "$w" | Should -Match 'unreachable'
        }
    }
    It 'warns and returns $null when the connect does not complete before the timeout' {
        InModuleScope woscap {
            # TEST-NET-1 (RFC 5737) is not routable, so the connect either hangs until the
            # timeout or faults; both paths must warn and return $null rather than block.
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $client = Connect-WoscapTcpClient -Server '192.0.2.1' -Port 9390 -TimeoutMs 500 `
                -Label 'test endpoint' -WarningVariable w -WarningAction SilentlyContinue
            $sw.Stop()
            $client | Should -BeNullOrEmpty
            "$w" | Should -Match 'unreachable'
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 15
        }
    }
    It 'labels the warning with the caller-supplied endpoint name' {
        InModuleScope woscap {
            $null = Connect-WoscapTcpClient -Server '127.0.0.1' -Port 1 -TimeoutMs 1000 `
                -Label 'Zabbix trapper' -WarningVariable w -WarningAction SilentlyContinue
            "$w" | Should -Match 'woscap: Zabbix trapper 127\.0\.0\.1:1'
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Connect-WoscapGmpStream' {
    It 'warns and returns $null when the connection is refused' {
        InModuleScope woscap {
            $conn = Connect-WoscapGmpStream -Server '127.0.0.1' -Port 1 -TimeoutMs 500 -WarningAction SilentlyContinue
            $conn | Should -BeNullOrEmpty
        }
    }
    It 'warns and returns $null when the TLS handshake fails (plain-text listener)' {
        InModuleScope woscap {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
            try {
                # Accept the socket but never speak TLS, so AuthenticateAsClient fails.
                $accept = $listener.AcceptTcpClientAsync()
                $conn = Connect-WoscapGmpStream -Server '127.0.0.1' -Port $port -TimeoutMs 1000 -WarningAction SilentlyContinue
                $conn | Should -BeNullOrEmpty
            } finally { $listener.Stop() }
        }
    }
}

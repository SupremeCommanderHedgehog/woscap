function Connect-WoscapGmpStream {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Server,
        [int] $Port = 9390,
        [int] $TimeoutMs = 30000,
        [switch] $SkipCertificateCheck
    )

    # Connect-with-timeout (and its unreachable warning) is shared with the other
    # socket integrations; $null here means it already warned.
    $client = Connect-WoscapTcpClient -Server $Server -Port $Port -TimeoutMs $TimeoutMs -Label 'OpenVAS GMP'
    if (-not $client) { return $null }

    $ssl = $null
    $netStream = $null
    try {
        # gvmd commonly presents a self-signed cert. With -SkipCertificateCheck we accept
        # any chain; otherwise the default policy applies and an untrusted cert fails the
        # handshake (caught below -> warn + $null).
        $validation = if ($SkipCertificateCheck) {
            [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $ch, $e) $true }
        } else { $null }

        # Bound the handshake by $TimeoutMs: set the transport timeouts BEFORE
        # AuthenticateAsClient, otherwise a peer that accepts the socket but never
        # negotiates TLS makes the blocking handshake read hang forever.
        $netStream = $client.GetStream()
        $netStream.ReadTimeout = $TimeoutMs
        $netStream.WriteTimeout = $TimeoutMs
        $ssl = [System.Net.Security.SslStream]::new($netStream, $false, $validation)
        $ssl.AuthenticateAsClient($Server)
        $ssl.ReadTimeout = $TimeoutMs
        $ssl.WriteTimeout = $TimeoutMs
        [pscustomobject]@{ Client = $client; Stream = $ssl }
    } catch {
        Write-Warning "woscap: OpenVAS GMP TLS handshake to ${Server}:${Port} failed: $_"
        if ($ssl) { $ssl.Dispose() }              # SslStream(leaveInnerStreamOpen=$false) also disposes $netStream
        elseif ($netStream) { $netStream.Dispose() }
        $client.Close(); return $null
    }
}

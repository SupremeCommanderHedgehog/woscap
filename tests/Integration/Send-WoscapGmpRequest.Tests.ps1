BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Send-WoscapGmpRequest' {
    It 'writes the request and returns the reply parsed as XML, even when chunked' {
        InModuleScope woscap {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
            try {
                $accept = $listener.AcceptTcpClientAsync()
                # Server runspace: read the request, then dribble the reply in two chunks
                # so the client must accumulate before the XML parses.
                $ps = [powershell]::Create()
                [void]$ps.AddScript({
                    param($accept)
                    $accept.Wait(5000) | Out-Null
                    $client = $accept.Result
                    $stream = $client.GetStream()
                    $buf = New-Object byte[] 4096
                    $n = $stream.Read($buf, 0, $buf.Length)
                    $req = [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
                    $part1 = [System.Text.Encoding]::UTF8.GetBytes('<authenticate_response status="200" status_text="OK">')
                    $part2 = [System.Text.Encoding]::UTF8.GetBytes('<role>Admin</role></authenticate_response>')
                    $stream.Write($part1, 0, $part1.Length); $stream.Flush()
                    Start-Sleep -Milliseconds 50
                    $stream.Write($part2, 0, $part2.Length); $stream.Flush()
                    $req
                }).AddArgument($accept)
                $handle = $ps.BeginInvoke()

                $client = [System.Net.Sockets.TcpClient]::new()
                $client.Connect('127.0.0.1', $port)
                $stream = $client.GetStream()
                $resp = Send-WoscapGmpRequest -Stream $stream -Request '<authenticate/>' -TimeoutMs 5000

                $resp | Should -BeOfType [System.Xml.XmlDocument]
                $resp.DocumentElement.GetAttribute('status') | Should -Be '200'

                $req = @($ps.EndInvoke($handle))[0]
                $ps.Dispose()
                $req | Should -Be '<authenticate/>'
                $client.Close()
            } finally { $listener.Stop() }
        }
    }
    It 'throws when the reply never becomes well-formed before the timeout' {
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
                    $buf = New-Object byte[] 4096
                    $stream.Read($buf, 0, $buf.Length) | Out-Null
                    $partial = [System.Text.Encoding]::UTF8.GetBytes('<authenticate_response status="200">')
                    $stream.Write($partial, 0, $partial.Length); $stream.Flush()
                    Start-Sleep -Milliseconds 500
                }).AddArgument($accept)
                $handle = $ps.BeginInvoke()

                $client = [System.Net.Sockets.TcpClient]::new()
                $client.Connect('127.0.0.1', $port)
                $stream = $client.GetStream()
                { Send-WoscapGmpRequest -Stream $stream -Request '<authenticate/>' -TimeoutMs 300 } | Should -Throw

                $ps.EndInvoke($handle) | Out-Null
                $ps.Dispose()
                $client.Close()
            } finally { $listener.Stop() }
        }
    }
    It 'reassembles a multibyte UTF-8 char split across a chunk boundary' {
        InModuleScope woscap {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
            try {
                $accept = $listener.AcceptTcpClientAsync()
                # Server runspace: split the reply's UTF-8 bytes in the MIDDLE of a
                # multibyte sequence so a naive per-chunk decode mangles the char.
                # Bytes are built explicitly (no non-ASCII source literal) so this test is
                # independent of how each PowerShell edition reads the .ps1 file encoding:
                # Windows PowerShell 5.1 reads a BOM-less file as the ANSI code page, which
                # would otherwise corrupt an inline non-ASCII literal.
                $ps = [powershell]::Create()
                [void]$ps.AddScript({
                    param($accept)
                    $accept.Wait(5000) | Out-Null
                    $client = $accept.Result
                    $stream = $client.GetStream()
                    $buf = New-Object byte[] 4096
                    $stream.Read($buf, 0, $buf.Length) | Out-Null
                    # <r status="200"><t>caf + [e-acute: C3 A9] + [em-dash: E2 80 94] + x</t></r>
                    $prefix = [System.Text.Encoding]::ASCII.GetBytes('<r status="200"><t>caf')
                    $eacute = [byte[]]@(0xC3, 0xA9)
                    $emdash = [byte[]]@(0xE2, 0x80, 0x94)
                    $suffix = [System.Text.Encoding]::ASCII.GetBytes('x</t></r>')
                    $all = [byte[]]($prefix + $eacute + $emdash + $suffix)
                    # Cut between the 1st and 2nd byte of the em-dash sequence.
                    $cut = $prefix.Length + $eacute.Length + 1
                    $stream.Write($all, 0, $cut); $stream.Flush()
                    Start-Sleep -Milliseconds 50
                    $stream.Write($all, $cut, $all.Length - $cut); $stream.Flush()
                }).AddArgument($accept)
                $handle = $ps.BeginInvoke()

                $client = [System.Net.Sockets.TcpClient]::new()
                $client.Connect('127.0.0.1', $port)
                $stream = $client.GetStream()
                $resp = Send-WoscapGmpRequest -Stream $stream -Request '<authenticate/>' -TimeoutMs 5000

                # Expected text also built from explicit UTF-8 bytes: caf + e-acute + em-dash + x
                $expected = [System.Text.Encoding]::UTF8.GetString([byte[]]@(0x63, 0x61, 0x66, 0xC3, 0xA9, 0xE2, 0x80, 0x94, 0x78))
                $resp.DocumentElement.SelectSingleNode('t').InnerText | Should -Be $expected

                $ps.EndInvoke($handle) | Out-Null
                $ps.Dispose()
                $client.Close()
            } finally { $listener.Stop() }
        }
    }
    It 'returns immediately for a self-closing root element' {
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
                    $stream = $accept.Result.GetStream()
                    $buf = New-Object byte[] 4096
                    $stream.Read($buf, 0, $buf.Length) | Out-Null
                    $reply = [System.Text.Encoding]::UTF8.GetBytes('<authenticate_response status="200" status_text="OK"/>')
                    $stream.Write($reply, 0, $reply.Length); $stream.Flush()
                }).AddArgument($accept)
                $handle = $ps.BeginInvoke()
                $client = [System.Net.Sockets.TcpClient]::new(); $client.Connect('127.0.0.1', $port)
                $resp = Send-WoscapGmpRequest -Stream $client.GetStream() -Request '<authenticate/>' -TimeoutMs 5000
                $resp.DocumentElement.GetAttribute('status') | Should -Be '200'
                $ps.EndInvoke($handle) | Out-Null; $ps.Dispose(); $client.Close()
            } finally { $listener.Stop() }
        }
    }
    It 'assembles a large multi-chunk report and parses it once complete' {
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
                    $stream = $accept.Result.GetStream()
                    $buf = New-Object byte[] 4096
                    $stream.Read($buf, 0, $buf.Length) | Out-Null
                    # ~200 KB body split across many writes; closing tag only in the final write.
                    $filler = '<result><name>' + ('x' * 500) + '</name></result>'
                    $body = '<get_reports_response status="200"><report>' + ($filler * 400) + '</report></get_reports_response>'
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $off = 0
                    while ($off -lt $bytes.Length) {
                        $len = [Math]::Min(8000, $bytes.Length - $off)
                        $stream.Write($bytes, $off, $len); $stream.Flush()
                        $off += $len
                    }
                }).AddArgument($accept)
                $handle = $ps.BeginInvoke()
                $client = [System.Net.Sockets.TcpClient]::new(); $client.Connect('127.0.0.1', $port)
                $resp = Send-WoscapGmpRequest -Stream $client.GetStream() -Request '<get_reports/>' -TimeoutMs 10000
                $resp.DocumentElement.Name | Should -Be 'get_reports_response'
                @($resp.SelectNodes('//result')).Count | Should -Be 400
                $ps.EndInvoke($handle) | Out-Null; $ps.Dispose(); $client.Close()
            } finally { $listener.Stop() }
        }
    }
    It 'detects the root closing tag even when split across chunk boundaries' {
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
                    $stream = $accept.Result.GetStream()
                    $buf = New-Object byte[] 4096
                    $stream.Read($buf, 0, $buf.Length) | Out-Null
                    $full = '<get_tasks_response status="200"><task><status>Done</status></task></get_tasks_response>'
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($full)
                    # split in the MIDDLE of the closing tag </get_tasks_response>
                    $cut = $full.LastIndexOf('_response>')  # lands inside the closing tag
                    $stream.Write($bytes, 0, $cut); $stream.Flush()
                    Start-Sleep -Milliseconds 50
                    $stream.Write($bytes, $cut, $bytes.Length - $cut); $stream.Flush()
                }).AddArgument($accept)
                $handle = $ps.BeginInvoke()
                $client = [System.Net.Sockets.TcpClient]::new(); $client.Connect('127.0.0.1', $port)
                $resp = Send-WoscapGmpRequest -Stream $client.GetStream() -Request '<get_tasks/>' -TimeoutMs 5000
                $resp.SelectSingleNode('//status').InnerText | Should -Be 'Done'
                $ps.EndInvoke($handle) | Out-Null; $ps.Dispose(); $client.Close()
            } finally { $listener.Stop() }
        }
    }
    It 'completes a self-closing root whose start tag is split across reads' {
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
                    $stream = $accept.Result.GetStream()
                    $buf = New-Object byte[] 4096; $stream.Read($buf, 0, $buf.Length) | Out-Null
                    # Name + attrs first, the trailing '/>' only in the second write.
                    $p1 = [System.Text.Encoding]::UTF8.GetBytes('<authenticate_response status="200" status_text="OK"')
                    $p2 = [System.Text.Encoding]::UTF8.GetBytes('/>')
                    $stream.Write($p1, 0, $p1.Length); $stream.Flush(); Start-Sleep -Milliseconds 60
                    $stream.Write($p2, 0, $p2.Length); $stream.Flush()
                }).AddArgument($accept)
                $handle = $ps.BeginInvoke()
                $client = [System.Net.Sockets.TcpClient]::new(); $client.Connect('127.0.0.1', $port)
                $resp = Send-WoscapGmpRequest -Stream $client.GetStream() -Request '<authenticate/>' -TimeoutMs 4000
                $resp.DocumentElement.GetAttribute('status') | Should -Be '200'
                $ps.EndInvoke($handle) | Out-Null; $ps.Dispose(); $client.Close()
            } finally { $listener.Stop() }
        }
    }
    It 'completes a self-closing root longer than the old 4096-char detection window' {
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
                    $stream = $accept.Result.GetStream()
                    $buf = New-Object byte[] 4096; $stream.Read($buf, 0, $buf.Length) | Out-Null
                    # A gvmd error reply with a long status_text: single self-closing element > 4096 chars.
                    $long = '<create_target_response status="400" status_text="' + ('x' * 5000) + '"/>'
                    $b = [System.Text.Encoding]::UTF8.GetBytes($long)
                    $stream.Write($b, 0, $b.Length); $stream.Flush()
                }).AddArgument($accept)
                $handle = $ps.BeginInvoke()
                $client = [System.Net.Sockets.TcpClient]::new(); $client.Connect('127.0.0.1', $port)
                $resp = Send-WoscapGmpRequest -Stream $client.GetStream() -Request '<create_target/>' -TimeoutMs 4000
                $resp.DocumentElement.GetAttribute('status') | Should -Be '400'
                $resp.DocumentElement.GetAttribute('status_text').Length | Should -Be 5000
                $ps.EndInvoke($handle) | Out-Null; $ps.Dispose(); $client.Close()
            } finally { $listener.Stop() }
        }
    }
    It 'learns the correct root name when the start tag name is split across reads' {
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
                    $stream = $accept.Result.GetStream()
                    $buf = New-Object byte[] 4096; $stream.Read($buf, 0, $buf.Length) | Out-Null
                    $p1 = [System.Text.Encoding]::UTF8.GetBytes('<get_tasks_respo')      # name split here
                    $p2 = [System.Text.Encoding]::UTF8.GetBytes('nse status="200"><task><status>Done</status></task></get_tasks_response>')
                    $stream.Write($p1, 0, $p1.Length); $stream.Flush(); Start-Sleep -Milliseconds 60
                    $stream.Write($p2, 0, $p2.Length); $stream.Flush()
                }).AddArgument($accept)
                $handle = $ps.BeginInvoke()
                $client = [System.Net.Sockets.TcpClient]::new(); $client.Connect('127.0.0.1', $port)
                $resp = Send-WoscapGmpRequest -Stream $client.GetStream() -Request '<get_tasks/>' -TimeoutMs 4000
                $resp.DocumentElement.Name | Should -Be 'get_tasks_response'
                $resp.SelectSingleNode('//status').InnerText | Should -Be 'Done'
                $ps.EndInvoke($handle) | Out-Null; $ps.Dispose(); $client.Close()
            } finally { $listener.Stop() }
        }
    }
    It 'completes when there is trailing whitespace after the root closing tag' {
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
                    $stream = $accept.Result.GetStream()
                    $buf = New-Object byte[] 4096; $stream.Read($buf, 0, $buf.Length) | Out-Null
                    $body = '<get_reports_response status="200"><report><results/></report></get_reports_response>' + ("`n" + (' ' * 40))
                    $b = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $stream.Write($b, 0, $b.Length); $stream.Flush()
                }).AddArgument($accept)
                $handle = $ps.BeginInvoke()
                $client = [System.Net.Sockets.TcpClient]::new(); $client.Connect('127.0.0.1', $port)
                $resp = Send-WoscapGmpRequest -Stream $client.GetStream() -Request '<get_reports/>' -TimeoutMs 4000
                $resp.DocumentElement.GetAttribute('status') | Should -Be '200'
                $ps.EndInvoke($handle) | Out-Null; $ps.Dispose(); $client.Close()
            } finally { $listener.Stop() }
        }
    }
    It 'detects a self-closing root even when an attribute value contains a raw > character' {
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
                    $stream = $accept.Result.GetStream()
                    $buf = New-Object byte[] 4096; $stream.Read($buf, 0, $buf.Length) | Out-Null
                    # Raw '>' inside status_text: the first '>' is NOT the tag end.
                    $b = [System.Text.Encoding]::UTF8.GetBytes('<create_target_response status="400" status_text="need port > 1024"/>')
                    $stream.Write($b, 0, $b.Length); $stream.Flush()
                }).AddArgument($accept)
                $handle = $ps.BeginInvoke()
                $client = [System.Net.Sockets.TcpClient]::new(); $client.Connect('127.0.0.1', $port)
                $resp = Send-WoscapGmpRequest -Stream $client.GetStream() -Request '<create_target/>' -TimeoutMs 4000
                $resp.DocumentElement.GetAttribute('status') | Should -Be '400'
                $resp.DocumentElement.GetAttribute('status_text') | Should -Be 'need port > 1024'
                $ps.EndInvoke($handle) | Out-Null; $ps.Dispose(); $client.Close()
            } finally { $listener.Stop() }
        }
    }
    It 'does not complete early on a root close tag echoed inside content' {
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
                    $stream = $accept.Result.GetStream()
                    $buf = New-Object byte[] 4096; $stream.Read($buf, 0, $buf.Length) | Out-Null
                    # First write ENDS with an echoed (CDATA-embedded) close tag so the tail check
                    # matches it; the buffer can't parse yet (CDATA unclosed), so the reader must
                    # keep reading to the real end in the second write.
                    $p1 = [System.Text.Encoding]::UTF8.GetBytes('<get_reports_response status="200"><report><![CDATA[oops</get_reports_response>')
                    $p2 = [System.Text.Encoding]::UTF8.GetBytes('still going]]></report></get_reports_response>')
                    $stream.Write($p1, 0, $p1.Length); $stream.Flush(); Start-Sleep -Milliseconds 60
                    $stream.Write($p2, 0, $p2.Length); $stream.Flush()
                }).AddArgument($accept)
                $handle = $ps.BeginInvoke()
                $client = [System.Net.Sockets.TcpClient]::new(); $client.Connect('127.0.0.1', $port)
                $resp = Send-WoscapGmpRequest -Stream $client.GetStream() -Request '<get_reports/>' -TimeoutMs 4000
                $resp.DocumentElement.GetAttribute('status') | Should -Be '200'
                $resp.SelectSingleNode('//report').InnerText | Should -Match 'still going'
                $ps.EndInvoke($handle) | Out-Null; $ps.Dispose(); $client.Close()
            } finally { $listener.Stop() }
        }
    }
}

function Send-WoscapGmpRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.IO.Stream] $Stream,
        [Parameter(Mandatory)] [string] $Request,
        [int] $TimeoutMs = 30000
    )

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Request)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()

    # GMP has no length prefix: the reply is exactly one XML element. Re-parsing the whole
    # (possibly multi-MB) buffer after every chunk is O(n^2) and makes a large get_reports
    # reply blow the time budget. Instead, detect completion by watching for the root
    # element's closing tag (or a self-closing root), then parse ONCE.
    # The overall timeout relies on a timeout-capable stream; NetworkStream/SslStream both
    # report CanTimeout=$true, so the per-read ReadTimeout below bounds each blocking read.
    $sb = [System.Text.StringBuilder]::new()
    $buffer = [byte[]]::new(8192)
    # Stateful streaming decoder: read boundaries are byte boundaries, so a multibyte UTF-8
    # char straddling two reads must not be decoded per-chunk; the decoder retains leftover
    # bytes between GetChars calls.
    $decoder = [System.Text.Encoding]::UTF8.GetDecoder()
    $charBuf = [char[]]::new($buffer.Length)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $rootName = $null          # root element name, learned from the first start tag
    $rootComplete = $false     # set once the full root element has been received

    while ($sw.Elapsed.TotalMilliseconds -lt $TimeoutMs) {
        if ($Stream.CanTimeout) { $Stream.ReadTimeout = [Math]::Max(1, $TimeoutMs - [int]$sw.Elapsed.TotalMilliseconds) }
        try {
            $n = $Stream.Read($buffer, 0, $buffer.Length)
        } catch {
            break   # ReadTimeout surfaces as IOException
        }
        if ($n -le 0) { break }
        $c = $decoder.GetChars($buffer, 0, $n, $charBuf, 0)
        [void]$sb.Append($charBuf, 0, $c)

        # Learn the root element name once (its start tag arrives in the first chunk).
        if (-not $rootName) {
            $prefix = $sb.ToString(0, [Math]::Min($sb.Length, 4096))
            $m = [regex]::Match($prefix, '<([A-Za-z_][\w.\-]*)')
            if ($m.Success) {
                $rootName = $m.Groups[1].Value
                # Self-closing root (e.g. <authenticate_response .../>): the first '>' is
                # preceded by '/'. GMP escapes '>' in attribute values, so the first '>'
                # is the end of the root start tag.
                $gt = $prefix.IndexOf('>', $m.Index)
                if ($gt -gt 0 -and $prefix[$gt - 1] -eq '/') { $rootComplete = $true }
            }
        }
        # Otherwise wait for the root closing tag. Scan only a bounded tail window (O(1)/chunk)
        # so total work stays O(n), not O(n^2).
        if ($rootName -and -not $rootComplete) {
            $close = "</$rootName>"
            $window = [Math]::Min($sb.Length, $close.Length + 16)
            $tail = $sb.ToString($sb.Length - $window, $window)
            if ($tail.TrimEnd().EndsWith($close)) { $rootComplete = $true }
        }

        if ($rootComplete) {
            try { return [xml]$sb.ToString() }
            catch { $rootComplete = $false }   # false alarm (rare) — keep reading until timeout
        }
    }
    throw "GMP response incomplete or unparseable after $($sb.Length) chars."
}

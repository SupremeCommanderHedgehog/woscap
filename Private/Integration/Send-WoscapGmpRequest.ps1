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
    # (possibly multi-MB) buffer after every chunk is O(n^2) and blows the time budget, so
    # detect completion structurally instead, then parse ONCE. Detection is chunking-robust:
    #  Phase 1 — learn the root element from its FULL start tag. Wait for the '>' that ends
    #    it (GMP escapes '>' in attribute values, so the first '>' after '<name' ends the
    #    tag). Deciding only on the complete tag avoids latching a name truncated at a read
    #    boundary and makes self-closing detection reliable regardless of chunk size.
    #  Phase 2 — if the root is not self-closing, wait for its closing tag, scanning a
    #    carry+chunk window so a close tag split across a read boundary still matches (O(n)).
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

    $rootName   = $null        # root element name, once its complete start tag is seen
    $closeTag   = $null        # "</root>" for an open root; stays $null for a self-closing root
    $probedRoot = $false       # whether the root start tag has been resolved

    while ($sw.Elapsed.TotalMilliseconds -lt $TimeoutMs) {
        if ($Stream.CanTimeout) { $Stream.ReadTimeout = [Math]::Max(1, $TimeoutMs - [int]$sw.Elapsed.TotalMilliseconds) }
        try {
            $n = $Stream.Read($buffer, 0, $buffer.Length)
        } catch {
            break   # ReadTimeout surfaces as IOException
        }
        if ($n -le 0) { break }
        $c = $decoder.GetChars($buffer, 0, $n, $charBuf, 0)
        if ($c -gt 0) { [void]$sb.Append($charBuf, 0, $c) }

        # Phase 1: resolve the root element from its COMPLETE start tag. Bound the scan
        # (a real GMP start tag is tiny), so a start tag that never terminates can't drive
        # an O(n^2) whole-buffer rescan. Find the tag's end honoring quotes, so a raw '>'
        # inside an attribute value isn't mistaken for the tag end (which would misjudge a
        # self-closing root and then wait forever for a close tag that never comes).
        if (-not $probedRoot) {
            $probe = $sb.ToString(0, [Math]::Min($sb.Length, 65536))
            $lt = $probe.IndexOf('<')
            while ($lt -ge 0 -and ($lt + 1) -lt $probe.Length -and $probe[$lt + 1] -notmatch '[A-Za-z_]') {
                $lt = $probe.IndexOf('<', $lt + 1)   # skip an XML declaration / comment / PI
            }
            if ($lt -ge 0 -and ($lt + 1) -lt $probe.Length) {
                $k = $lt + 1; $quote = [char]0; $gt = -1
                while ($k -lt $probe.Length) {
                    $ch = $probe[$k]
                    if ($quote -ne [char]0) { if ($ch -eq $quote) { $quote = [char]0 } }
                    elseif ($ch -eq '"' -or $ch -eq "'") { $quote = $ch }
                    elseif ($ch -eq '>') { $gt = $k; break }
                    $k++
                }
                if ($gt -ge 0) {
                    $tag = $probe.Substring($lt, $gt - $lt + 1)   # the complete start tag
                    $m = [regex]::Match($tag, '^<([A-Za-z_][\w.\-]*)')
                    if ($m.Success) {
                        $rootName = $m.Groups[1].Value
                        if (-not $tag.EndsWith('/>')) { $closeTag = "</$rootName>" }
                        $probedRoot = $true
                    }
                }
            }
        }

        # Phase 2: the reply is complete when the buffer's trimmed tail is the root close
        # tag (open root) or a self-close '/>' (self-closing root). VERIFY by parsing, so a
        # close tag echoed inside content — which can't yet balance — is rejected and we keep
        # reading. Parsing runs ~once (at the true end), not per chunk, so this stays O(n).
        if ($probedRoot) {
            $need = if ($closeTag) { $closeTag.Length } else { 2 }
            $tailLen = [Math]::Min($sb.Length, $need + 64)
            $tail = $sb.ToString($sb.Length - $tailLen, $tailLen).TrimEnd()
            $atEnd = if ($closeTag) { $tail.EndsWith($closeTag) } else { $tail.EndsWith('/>') }
            if ($atEnd) {
                try { return [xml]$sb.ToString() } catch { }   # not actually balanced yet; keep reading
            }
        }
    }
    throw "GMP response incomplete or unparseable after $($sb.Length) chars."
}

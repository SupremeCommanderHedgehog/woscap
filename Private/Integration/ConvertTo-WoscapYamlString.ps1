function ConvertTo-WoscapYamlString {
    <#
    .SYNOPSIS
        Renders a string as a YAML double-quoted scalar that parses back to the same string.
    .DESCRIPTION
        Escapes backslash and double quote, and escapes every character outside printable
        ASCII: C0/C1 controls and DEL as \xHH, other BMP characters (including U+2028 and
        U+2029, which YAML treats as line breaks) as \uHHHH, and surrogate pairs as
        \UHHHHHHHH. The output is therefore pure ASCII on one line, so the value can
        contain colons, '#', quotes, line breaks, or YAML keywords such as 'yes' without
        changing the YAML structure or being re-typed.
    .PARAMETER Value
        The text to quote. An empty string yields "".
    .EXAMPLE
        ConvertTo-WoscapYamlString 'Audit policy: Logon'   # -> "Audit policy: Logon"
    .EXAMPLE
        ConvertTo-WoscapYamlString '10'                    # -> "10" (stays a string)
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Value)

    $sb = [System.Text.StringBuilder]::new('"')
    for ($i = 0; $i -lt $Value.Length; $i++) {
        $c = $Value[$i]
        $n = [int]$c
        if ($c -eq '\' -or $c -eq '"') { [void]$sb.Append('\').Append($c) }
        elseif ($n -ge 0x20 -and $n -lt 0x7F) { [void]$sb.Append($c) }
        elseif ($n -lt 0x100) { [void]$sb.AppendFormat('\x{0:X2}', $n) }
        elseif ([char]::IsHighSurrogate($c) -and ($i + 1) -lt $Value.Length -and [char]::IsLowSurrogate($Value[$i + 1])) {
            [void]$sb.AppendFormat('\U{0:X8}', [char]::ConvertToUtf32($c, $Value[$i + 1]))
            $i++
        }
        else { [void]$sb.AppendFormat('\u{0:X4}', $n) }
    }
    [void]$sb.Append('"')
    $sb.ToString()
}

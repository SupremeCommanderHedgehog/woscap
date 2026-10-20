function ConvertTo-WoscapYamlString {
    <#
    .SYNOPSIS
        Renders a string as a YAML double-quoted scalar.
    .DESCRIPTION
        Escapes backslash, double quote, and every control character, so the value can
        contain colons, '#', quotes, or newlines without changing the YAML structure.
    .PARAMETER Value
        The text to quote. An empty string yields "".
    .EXAMPLE
        ConvertTo-WoscapYamlString 'Audit policy: Logon'   # -> "Audit policy: Logon"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Value)

    $sb = [System.Text.StringBuilder]::new('"')
    foreach ($c in $Value.ToCharArray()) {
        if ($c -eq '\' -or $c -eq '"') { [void]$sb.Append('\').Append($c) }
        elseif ([int]$c -lt 0x20 -or [int]$c -eq 0x7F) { [void]$sb.AppendFormat('\x{0:X2}', [int]$c) }
        else { [void]$sb.Append($c) }
    }
    [void]$sb.Append('"')
    $sb.ToString()
}

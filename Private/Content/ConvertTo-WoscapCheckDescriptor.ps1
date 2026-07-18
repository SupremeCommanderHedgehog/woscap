function ConvertTo-WoscapCheckDescriptor {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [pscustomobject] $Rule)

    # Extract an automated Registry check descriptor from a DISA rule whose check-content states
    # the registry inline (the Microsoft Edge STIG style): "... navigate to the following key:
    # HKLM\...  If the value for "Name" is not set to "REG_TYPE = value", this is a finding."
    # Returns $null whenever a single scalar registry value cannot be read unambiguously — a
    # Group-Policy-only rule, a manual/version check, a list-subkey entry, a rule naming more than
    # one key or value, a multi-value range, or a value type/size that isn't a scalar. Callers drop
    # the $null and leave that rule Not_Reviewed. This NEVER guesses and NEVER fails open: the key,
    # value name, and expected value all come from the source prose, and any ambiguity yields $null.
    $flat = ConvertTo-WoscapFlatCheckText -Text ([string] $Rule.CheckText)
    if (-not $flat) { return $null }

    # Ambiguity guard: exactly one registry key mention and exactly one "is not set to REG_..."
    # value clause, else we cannot know which key/value pairing is intended -> fail closed.
    if (([regex]::Matches($flat, '(?i)navigate to the following (?:registry )?key:').Count -ne 1) -or
        ([regex]::Matches($flat, '(?i)\bis not set to\s*"REG_').Count -ne 1)) { return $null }

    $keyM = [regex]::Match($flat, '(?i)navigate to the following (?:registry )?key:\s*(?<key>HK(?:LM|CU)\\[^\s".,;]+)')
    $valM = [regex]::Match($flat, '(?i)If the value (?:for|of)\s*"?(?<name>[^"\s]+)"?\s+is not set to\s*"(?<type>REG_[A-Z_]+)\s*=\s*(?<val>[^"]*)"')
    if (-not ($keyM.Success -and $valM.Success)) { return $null }

    $key  = $keyM.Groups['key'].Value.TrimEnd('\')
    $path = $key -replace '^(?i)HKLM\\', 'HKLM:\' -replace '^(?i)HKCU\\', 'HKCU:\'
    $name = $valM.Groups['name'].Value.Trim().Trim('"')
    $type = $valM.Groups['type'].Value.ToUpperInvariant()
    $raw  = $valM.Groups['val'].Value.Trim()

    # The value name must be a bare registry identifier. Reject a purely numeric name (a list-subkey
    # entry such as URLAllowlist\1) and anything carrying stray punctuation from a loose capture.
    if ($name -notmatch '^[A-Za-z][A-Za-z0-9_]*$') { return $null }

    if ($type -in @('REG_DWORD', 'REG_QWORD')) {
        # Only a single clean scalar (decimal, hex, or "0x.. (dec)") is representable — a range or
        # alternative like "1 or 2" must stay Not_Reviewed rather than silently taking the first int.
        if ($raw -notmatch '^(?:0x[0-9a-fA-F]+|-?\d+)(?:\s*\(\s*-?\d+\s*\))?$') { return $null }
        try {
            $n = if     ($raw -match '\((-?\d+)\)')      { [int64] $matches[1] }
                 elseif ($raw -match '0x([0-9a-fA-F]+)') { [Convert]::ToInt64($matches[1], 16) }
                 else                                    { [int64] $raw }
        } catch { return $null }   # value outside Int64 range -> fail closed, don't crash generation
        $expected = if ($n -ge [int]::MinValue -and $n -le [int]::MaxValue) { [int] $n } else { $n }
    } elseif ($type -in @('REG_SZ', 'REG_EXPAND_SZ')) {
        $expected = $raw   # scalar string
    } else {
        return $null       # REG_MULTI_SZ (string[]), REG_BINARY, etc. — not a scalar 'eq' comparison
    }

    @{
        Type     = 'Registry'
        Path     = $path
        Name     = $name
        Operator = 'eq'
        Expected = $expected
    }
}

function ConvertTo-WoscapChromePolicyDescriptor {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [pscustomobject] $Rule)

    # Extract a Registry check descriptor from a Google Chrome STIG rule. Chrome's check-content
    # uses the in-browser chrome://policy method and states NO registry path, but Chrome policies
    # map deterministically to HKLM\SOFTWARE\Policies\Google\Chrome\<PolicyName> (Google's
    # documented, universal location — the policy name IS the registry value name). The policy name
    # and required value come from the STIG prose (not invented); only the fixed root is injected
    # and the REG type is inferred from the value form.
    #
    # Fail-closed — returns $null for anything that is not a single boolean/integer scalar policy:
    # list/allowlist policies (registry subkeys), organization-specific strings, multi-value ("1 or
    # 2") requirements, and version/enrollment checks with no stated value.
    #
    # A Chrome rule states one policy but often via TWO methods (chrome://policy "Universal method"
    # AND a "Windows method" naming HKLM\Software\Policies\Google\Chrome and the same value), so we
    # match the first "If <Name> ... is not set to <value>" clause. The generator assumes one policy
    # per rule (true for the Chrome STIG); the Windows method, present in ~half the rules,
    # independently corroborates the extracted value, and every emitted descriptor is verified
    # against the source check-text before it is committed.
    $flat = ConvertTo-WoscapFlatCheckText -Text ([string] $Rule.CheckText)
    if (-not $flat) { return $null }

    # "If [the policy] <Name> ... is not set to <value> [under the "Policy Value" column]..."
    $m = [regex]::Match($flat, '(?i)\bIf (?:the policy\s+)?["'']?(?<name>[A-Za-z][A-Za-z0-9_]{3,})["'']?\b[^.]*?\bis not (?:set|configured) to\s+["'']?(?<val>[^,."'']+?)["'']?\s*(?:under\b|[,.]|$)')
    if (-not $m.Success) { return $null }

    $name = $m.Groups['name'].Value.Trim()
    $raw  = $m.Groups['val'].Value.Trim()

    if ($name -notmatch '^[A-Za-z][A-Za-z0-9_]*$') { return $null }

    # Only a single boolean / integer scalar is representable as one Registry descriptor.
    $expected = $null
    if     ($raw -match '^(?i)false$') { $expected = 0 }
    elseif ($raw -match '^(?i)true$')  { $expected = 1 }
    elseif ($raw -match '^-?\d+$')     {
        try { $n = [int64] $raw } catch { return $null }
        if ($n -lt [int]::MinValue -or $n -gt [int]::MaxValue) { return $null }   # not a REG_DWORD
        $expected = [int] $n
    } else { return $null }   # wildcard "*", "1 or 2", org-specific strings, etc.

    @{
        Type     = 'Registry'
        Path     = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
        Name     = $name
        Operator = 'eq'
        Expected = $expected
    }
}

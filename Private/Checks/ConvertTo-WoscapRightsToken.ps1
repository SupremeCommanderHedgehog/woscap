function ConvertTo-WoscapRightsToken {
    <#
    .SYNOPSIS
        Normalize an ACE rights string into comparable tokens.
    .DESCRIPTION
        FileSystemRights/RegistryRights only stringify to names when the bit
        pattern maps onto named enum members. Inherit-only ACEs carrying GENERIC
        bits render as bare integers instead - a stock Windows 11 C:\Windows ACL
        contains 'BUILTIN\Users | -1610612736' and 'CREATOR OWNER | 268435456'
        next to the readable 'ReadAndExecute, Synchronize'.

        A numeric token matches nothing in MaxRights, so before this the stock
        ACL reported BUILTIN\Users as an offender and WN11-00-000095 was Open on
        an untouched install. Generic bits are expanded to the concrete rights
        they confer so they compare against the same vocabulary content uses.
    #>
    [CmdletBinding()]
    param([AllowNull()] [string] $Rights)

    if ([string]::IsNullOrWhiteSpace($Rights)) { return @() }

    # Win32 GENERIC_* constants, as they appear in an access mask.
    $genericAll     = 0x10000000
    $genericExecute = 0x20000000
    $genericWrite   = 0x40000000
    $genericRead    = -2147483648   # 0x80000000 as a signed int32

    $tokens = New-Object System.Collections.Generic.List[string]
    foreach ($raw in @(($Rights -split ',\s*') | Where-Object { $_ })) {
        $token = $raw.Trim()
        $numeric = 0
        if ([int]::TryParse($token, [ref]$numeric)) {
            if ($numeric -band $genericAll)     { $tokens.Add('FullControl') }
            if ($numeric -band $genericWrite)   { $tokens.Add('Write') }
            if ($numeric -band $genericRead)    { $tokens.Add('Read') }
            if ($numeric -band $genericExecute) { $tokens.Add('ExecuteFile'); $tokens.Add('ReadAndExecute') }
            # Bits outside the GENERIC range are kept verbatim so an unexpected
            # mask still registers as excess rather than vanishing.
            $known = $genericAll -bor $genericWrite -bor $genericExecute -bor $genericRead
            if (($numeric -band (-bnot $known)) -ne 0) { $tokens.Add($token) }
        } else {
            $tokens.Add($token)
        }
    }
    $tokens.ToArray()
}

function Invoke-AuditPolRaw {
    <#
    .SYNOPSIS
        Launch auditpol.exe and return its CSV output. Uncached.
    #>
    [CmdletBinding()]
    param()
    (& auditpol.exe /get /category:* /r 2>$null) -join "`n"
}

function Invoke-AuditPol {
    <#
    .SYNOPSIS
        auditpol CSV output, memoized for the life of one scan.
    .DESCRIPTION
        The Windows 11 pack carries around forty AuditPolicy rules, each of
        which reads through this. One process launch per scan, not per rule.
    #>
    [CmdletBinding()]
    param()
    Get-WoscapCachedValue -Key 'auditpol:all' -Producer { Invoke-AuditPolRaw }
}

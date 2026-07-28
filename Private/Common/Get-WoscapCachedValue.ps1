function Get-WoscapCachedValue {
    <#
    .SYNOPSIS
        Return a memoized reading, invoking Producer only on a cache miss.
    .DESCRIPTION
        Readings are wrapped in a single-element hashtable before storage so a
        $null or empty-collection reading still registers as "already read" and
        does not re-invoke the producer. A producer that throws is not cached,
        so a transient failure (for example a missing elevation) can recover on
        a later call rather than poisoning the whole scan.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Key,
        [Parameter(Mandatory)] [scriptblock] $Producer
    )
    if (-not $script:WoscapReadCache.ContainsKey($Key)) {
        $script:WoscapReadCache[$Key] = @{ Value = (& $Producer) }
    }
    # Emitting a collection bare unrolls it into the pipeline, so an EMPTY
    # cached collection reached the caller as $null - a different reading
    # entirely, and one that passes the ne/notin/setequals family. The unary
    # comma protects it; PowerShell unwraps the outer array on assignment, so
    # the caller sees the original collection including when it is empty.
    #
    # Applied only to collections: Write-Output -NoEnumerate would have done it
    # uniformly but wraps scalars and PSCustomObjects in a List[object], which
    # would break every scalar reading and the unreadable sentinel.
    $value = $script:WoscapReadCache[$Key].Value
    if ($null -ne $value -and $value -is [System.Collections.ICollection]) { return ,$value }
    $value
}

function Get-WoscapRequiredRegKind {
    <#
    .SYNOPSIS
        The registry value kinds a Registry descriptor accepts.
    .DESCRIPTION
        Pure function: never reads the machine. Returns
        @{ Kinds = <string[] of RegistryValueKind names, or '*'>; Error = <string or $null> }.
        Exactly one of Kinds and Error is set.

        A declared Kind wins:
            dword        -> DWord
            qword        -> QWord
            string       -> String, ExpandString
            expandstring -> ExpandString
            multistring  -> MultiString
        dword/qword need integer Expected values. string/expandstring take
        string Expected values with eq/ne/in/notin/regex, and integer values
        (a REG_SZ holding a number) with eq/ne/ge/le/in/notin. multistring
        takes the set operators. Any of them may use exists.

        Without a declared Kind the kinds are inferred from Operator and the
        element types of Expected:
            exists                                         -> '*' (any kind)
            eq ne ge le in notin, all integers             -> DWord
            eq ne in notin regex, all strings              -> String, ExpandString
            setequals subsetof supersetof sequence includes -> MultiString

        Every other combination - an unknown Kind or Operator, a missing
        Operator, an empty or null Expected, mixed element types, ge/le on a
        string - returns an Error. Binary is never accepted.
    .PARAMETER Descriptor
        A Registry check descriptor hashtable (Operator, Expected, optional Kind).
    .EXAMPLE
        Get-WoscapRequiredRegKind -Descriptor @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
        Returns @{ Kinds = @('DWord'); Error = $null }.
    .EXAMPLE
        Get-WoscapRequiredRegKind -Descriptor @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='ge'; Expected='5' }
        Returns an Error: ge compares numerically, so it needs an integer Expected.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Descriptor)

    $fail = { param($Message) @{ Kinds = $null; Error = $Message } }
    $ok   = {
        param($Kinds)
        $r = @{ Kinds = $null; Error = $null }
        if ($Kinds -eq '*') { $r['Kinds'] = '*' } else { $r['Kinds'] = [string[]]@($Kinds) }
        $r
    }

    if (-not $Descriptor.ContainsKey('Operator') -or [string]::IsNullOrEmpty([string]$Descriptor.Operator)) {
        return (& $fail 'Registry descriptor declares no Operator, so its value kind cannot be determined')
    }
    $op = [string]$Descriptor.Operator
    $setOps = @('setequals', 'subsetof', 'supersetof', 'sequence', 'includes')
    $known = @('eq', 'ne', 'ge', 'le', 'in', 'notin', 'regex', 'exists') + $setOps
    if ($known -notcontains $op) { return (& $fail "Registry operator '$op' is unknown") }

    # Classify Expected's elements: 'int', 'string', 'mixed', or 'none'.
    $intTypes = @([int], [long], [uint32], [int16], [uint16], [uint64], [byte], [sbyte])
    $exp = if ($Descriptor.ContainsKey('Expected')) { $Descriptor.Expected } else { $null }
    $elements = @(if ($null -ne $exp) { $exp })
    $shape = 'none'
    foreach ($e in $elements) {
        $t = if ($null -eq $e) { 'other' }
             elseif ($e -is [string]) { 'string' }
             elseif (@($intTypes | Where-Object { $e -is $_ }).Count -gt 0) { 'int' }
             else { 'other' }
        if ($shape -eq 'none') { $shape = $t } elseif ($shape -ne $t) { $shape = 'mixed' }
    }
    $expDesc = if ($shape -eq 'none') { 'an empty or null Expected' } else { "Expected of element type '$shape'" }

    $kindMap = @{
        'dword'        = @('DWord')
        'qword'        = @('QWord')
        'string'       = @('String', 'ExpandString')
        'expandstring' = @('ExpandString')
        'multistring'  = @('MultiString')
    }

    if ($Descriptor.ContainsKey('Kind')) {
        $kind = [string]$Descriptor.Kind
        if (-not $kindMap.ContainsKey($kind) -or $kind -cne $kind.ToLowerInvariant()) {
            return (& $fail "Registry Kind '$kind' is unknown (expected dword, qword, string, expandstring or multistring)")
        }
        if ($op -eq 'exists') { return (& $ok $kindMap[$kind]) }
        $allowed = switch ($kind) {
            { $_ -in @('dword', 'qword') } {
                if ($shape -eq 'int' -and $op -in @('eq', 'ne', 'ge', 'le', 'in', 'notin')) { $true } else { $false }
            }
            { $_ -in @('string', 'expandstring') } {
                ($shape -eq 'string' -and $op -in @('eq', 'ne', 'in', 'notin', 'regex')) -or
                ($shape -eq 'int' -and $op -in @('eq', 'ne', 'ge', 'le', 'in', 'notin'))
            }
            'multistring' { $op -in $setOps }
        }
        if (-not $allowed) {
            return (& $fail "Registry Kind '$kind' cannot be compared with operator '$op' and $expDesc")
        }
        return (& $ok $kindMap[$kind])
    }

    if ($op -eq 'exists') { return (& $ok '*') }
    if ($op -in $setOps) { return (& $ok @('MultiString')) }
    if ($shape -eq 'int' -and $op -in @('eq', 'ne', 'ge', 'le', 'in', 'notin')) { return (& $ok @('DWord')) }
    if ($shape -eq 'string' -and $op -in @('eq', 'ne', 'in', 'notin', 'regex')) { return (& $ok @('String', 'ExpandString')) }
    & $fail "Registry operator '$op' with $expDesc has no inferable value kind; declare Kind or correct Expected"
}

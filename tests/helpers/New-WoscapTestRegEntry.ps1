function global:New-WoscapTestRegEntry {
    <#
    .SYNOPSIS
        Test-only: build the { Value; Kind } shape Get-RegValueEntry returns.
    .DESCRIPTION
        Defined global so Mock bodies running inside InModuleScope woscap can
        call it. Without -Kind the kind is inferred from the .NET type the way
        the registry would return it:
            [int] / [uint32] / [int16] -> DWord
            [long]                     -> QWord
            [string]                   -> String
            [string[]] / [object[]] of strings -> MultiString
            [byte[]]                   -> Binary
        $null stays $null (absent). An unreadable sentinel is returned
        unchanged. Any other type throws, so a test cannot silently mock a
        kind the registry never produces.
    .PARAMETER Value
        The stored value, $null for absent, or an unreadable sentinel.
    .PARAMETER Kind
        RegistryValueKind name to report instead of the inferred one, e.g.
        'ExpandString' for a string value stored as REG_EXPAND_SZ.
    .EXAMPLE
        Mock Get-RegValueEntry { New-WoscapTestRegEntry 1 }
        The value reads as DWord 1.
    .EXAMPLE
        Mock Get-RegValueEntry { New-WoscapTestRegEntry '%SystemRoot%' -Kind ExpandString }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)] [AllowNull()] [object] $Value,
        [ValidateSet('String', 'ExpandString', 'MultiString', 'DWord', 'QWord', 'Binary', 'None', 'Unknown')]
        [string] $Kind
    )
    if ($null -eq $Value) { return $null }
    if ($Value.PSObject.TypeNames -contains 'Woscap.Unreadable') { return $Value }
    if (-not $Kind) {
        $Kind = if ($Value -is [byte[]]) { 'Binary' }
                elseif ($Value -is [int] -or $Value -is [uint32] -or $Value -is [int16]) { 'DWord' }
                elseif ($Value -is [long]) { 'QWord' }
                elseif ($Value -is [string]) { 'String' }
                elseif ($Value -is [array] -and @($Value | Where-Object { $_ -isnot [string] }).Count -eq 0) { 'MultiString' }
                else { throw "New-WoscapTestRegEntry: no registry kind for a value of type $($Value.GetType().FullName)" }
    }
    if ($Kind -eq 'MultiString') { $Value = [string[]]@($Value) }
    [pscustomobject]@{ Value = $Value; Kind = $Kind }
}

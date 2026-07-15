function Test-WoscapSameHost {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Position = 0)] [AllowNull()] [AllowEmptyString()] [string] $A,
        [Parameter(Position = 1)] [AllowNull()] [AllowEmptyString()] [string] $B
    )
    if ([string]::IsNullOrEmpty($A) -or [string]::IsNullOrEmpty($B)) { return $false }
    $a = $A.ToLowerInvariant()
    $b = $B.ToLowerInvariant()
    $a -eq $b -or $a.StartsWith($b + '.') -or $b.StartsWith($a + '.')
}

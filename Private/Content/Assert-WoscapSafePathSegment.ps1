function Assert-WoscapSafePathSegment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Segment,
        [Parameter(Mandatory)] [string] $Kind
    )

    # A safe cache path segment: letters/digits/dot/dash/underscore only, and NOT
    # '.'/'..' (which -LiteralPath still normalizes, escaping the cache root).
    if ($Segment -eq '.' -or $Segment -eq '..' -or $Segment -notmatch '^[\w.\-]+$') {
        throw "woscap: unsafe $Kind '$Segment'; it must contain only letters, digits, dot, dash, or underscore and cannot be '.' or '..'."
    }
}

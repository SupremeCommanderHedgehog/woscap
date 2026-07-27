function ConvertTo-WoscapBool {
    <#
        .SYNOPSIS
        Coerce a -Config value into a [bool], honoring the shared truthy vocabulary.

        .DESCRIPTION
        Config entries reach woscap from psd1/JSON as well as from real booleans, so a
        flag may arrive as 'false'/'0'/'no'/'off', all of which are truthy non-empty
        strings to PowerShell. Strings are matched against one vocabulary
        (1/true/yes/on, case- and whitespace-insensitive) so every -Config entry point
        accepts exactly the same words; anything else falls back to a plain [bool] cast.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Position = 0)] [AllowNull()] $Value
    )
    if ($Value -is [string]) { return [bool] ($Value.Trim() -match '^(1|true|yes|on)$') }
    [bool] $Value
}

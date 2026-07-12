function Export-WoscapJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Result,
        [Parameter(Mandatory)] [string] $Path
    )
    # -InputObject (not pipeline) so a single-element array still serializes as a JSON array.
    Write-WoscapText -Text (ConvertTo-Json -InputObject @($Result) -Depth 6) -Path $Path
}

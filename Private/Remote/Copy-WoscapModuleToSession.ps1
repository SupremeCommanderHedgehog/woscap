function Copy-WoscapModuleToSession {
    # Thin, untested seam over Copy-Item -ToSession so callers are mockable.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Session,
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Destination
    )
    Copy-Item -ToSession $Session -Path $Path -Destination $Destination -Recurse -Force
}

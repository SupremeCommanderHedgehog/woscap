function Remove-WoscapSession {
    # Thin, untested seam over Remove-PSSession so callers are mockable.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Session)
    if ($Session.Count -gt 0) { Remove-PSSession -Session $Session -ErrorAction SilentlyContinue }
}

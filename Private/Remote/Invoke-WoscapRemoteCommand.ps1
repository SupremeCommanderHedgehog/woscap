function Invoke-WoscapRemoteCommand {
    # Thin, untested seam over Invoke-Command -Session so callers are mockable
    # (Pester keeps Invoke-Command's real [PSSession] type on -Session otherwise).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Session,
        [Parameter(Mandatory)] [scriptblock] $ScriptBlock,
        [object[]] $ArgumentList
    )
    $p = @{ Session = $Session; ScriptBlock = $ScriptBlock }
    if ($PSBoundParameters.ContainsKey('ArgumentList')) { $p['ArgumentList'] = $ArgumentList }
    Invoke-Command @p
}

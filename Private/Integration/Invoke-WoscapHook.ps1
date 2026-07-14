function Invoke-WoscapHook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Plugin,
        [Parameter(Mandatory)] [string] $Hook,
        [hashtable] $Arguments = @{}
    )

    if (-not $Plugin.Hooks.ContainsKey($Hook)) {
        Write-Warning "woscap: plugin '$($Plugin.Name)' does not offer hook '$Hook'."
        return
    }
    try {
        & $Plugin.Hooks[$Hook] @Arguments
    } catch {
        Write-Warning "woscap: integration '$($Plugin.Name)' hook '$Hook' failed: $_"
        return
    }
}

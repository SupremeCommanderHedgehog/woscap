function Get-WoscapGuiConfigOptions {
    <#
        The plugin's ConfigOptions entries whose Hooks include -Hook, in declared order.
        Returns $null when the plugin declares no schema (the caller then offers the generic
        Key/Type/Value grid) and an empty list when the schema has nothing for this hook.
        Uses ConfigOptions on the plugin object when present, else reads <Path>\plugin.psd1
        (the loader does not carry ConfigOptions today).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Plugin,
        [Parameter(Mandatory)][string] $Hook
    )
    $schema = $null
    if (($Plugin -is [hashtable] -and $Plugin.ContainsKey('ConfigOptions')) -or
        ($Plugin -isnot [hashtable] -and $Plugin.PSObject.Properties['ConfigOptions'])) {
        $schema = @(Get-WoscapObjectProperty $Plugin 'ConfigOptions' @())
    } else {
        $path = [string](Get-WoscapObjectProperty $Plugin 'Path' '')
        $manifestPath = if ($path) { Join-Path $path 'plugin.psd1' } else { '' }
        if (-not $manifestPath -or -not (Test-Path -LiteralPath $manifestPath)) { return $null }
        $manifest = Import-PowerShellDataFile -LiteralPath $manifestPath
        if (-not $manifest.ContainsKey('ConfigOptions')) { return $null }
        $schema = @($manifest.ConfigOptions)
    }
    $hits = @(foreach ($o in $schema) {
        if ($o -is [hashtable] -and $o.ContainsKey('Hooks') -and (@($o.Hooks) -contains $Hook)) { $o }
    })
    # Comma keeps an empty list distinct from $null at the caller.
    , $hits
}

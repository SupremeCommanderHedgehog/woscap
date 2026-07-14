function Get-WoscapPluginRoot {
    [CmdletBinding()]
    param([string] $Path)

    if ($Path) { return $Path }
    Join-Path $script:WoscapModuleRoot 'Integrations'
}

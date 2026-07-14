function Resolve-WoscapIntegrationPlugin {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Integration, [string] $PluginPath)
    $folder = if ($PluginPath) { $PluginPath } else { Join-Path (Get-WoscapPluginRoot) $Integration }
    $plugin = Import-WoscapPlugin -Path $folder
    if (-not $plugin) { Write-Warning "woscap: integration '$Integration' unavailable."; return }
    $plugin
}

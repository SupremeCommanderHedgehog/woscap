function Invoke-WoscapIntegration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Integration,
        [hashtable] $Config = @{},
        [string] $PluginPath
    )

    $plugin = Resolve-WoscapIntegrationPlugin -Integration $Integration -PluginPath $PluginPath
    if (-not $plugin) { return }

    Invoke-WoscapHook -Plugin $plugin -Hook 'Invoke-ExternalScan' -Arguments @{ Config = $Config }
}

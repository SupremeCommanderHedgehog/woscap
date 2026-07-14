function Export-WoscapIntegration {
    [CmdletBinding(DefaultParameterSetName = 'Export')]
    param(
        [Parameter(Mandatory)] [string] $Integration,
        [Parameter(Mandatory)] [object[]] $Result,
        [Parameter(ParameterSetName = 'Remediation', Mandatory)] [switch] $Remediation,
        [Parameter(ParameterSetName = 'Remediation', Mandatory)] [string] $Path,
        [hashtable] $Config = @{},
        [string] $PluginPath
    )

    $plugin = Resolve-WoscapIntegrationPlugin -Integration $Integration -PluginPath $PluginPath
    if (-not $plugin) { return }

    switch ($PSCmdlet.ParameterSetName) {
        'Remediation' {
            Invoke-WoscapHook -Plugin $plugin -Hook 'New-Remediation' -Arguments @{ Result = $Result; Path = $Path; Config = $Config }
        }
        default {
            Invoke-WoscapHook -Plugin $plugin -Hook 'Export-Findings' -Arguments @{ Result = $Result; Config = $Config }
        }
    }
}

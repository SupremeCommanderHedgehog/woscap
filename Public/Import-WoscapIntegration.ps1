function Import-WoscapIntegration {
    [CmdletBinding(DefaultParameterSetName = 'Targets')]
    param(
        [Parameter(Mandatory)] [string] $Integration,
        [Parameter(ParameterSetName = 'Targets')] [switch] $Targets,
        [Parameter(ParameterSetName = 'Findings')] [switch] $Findings,
        [Parameter(ParameterSetName = 'Targets')] [string] $Source,
        [Parameter(ParameterSetName = 'Findings')] [string] $Path,
        [Parameter(ParameterSetName = 'Findings')] [object[]] $CorrelateWith,
        [hashtable] $Config = @{},
        [string] $PluginPath
    )

    $plugin = Resolve-WoscapIntegrationPlugin -Integration $Integration -PluginPath $PluginPath
    if (-not $plugin) { return }

    switch ($PSCmdlet.ParameterSetName) {
        'Targets' {
            Invoke-WoscapHook -Plugin $plugin -Hook 'Get-Targets' -Arguments @{ Source = $Source; Config = $Config }
        }
        'Findings' {
            $imported = Invoke-WoscapHook -Plugin $plugin -Hook 'Import-Findings' -Arguments @{ Path = $Path; Config = $Config }
            if ($PSBoundParameters.ContainsKey('CorrelateWith')) {
                Join-WoscapFinding -Results @($CorrelateWith) -Findings @($imported)
            } else {
                $imported
            }
        }
    }
}

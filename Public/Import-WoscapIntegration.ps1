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
                # Normalize HostMap into a fresh (case-insensitive) hashtable; accept any IDictionary
                # (e.g. [ordered] from Import-PowerShellDataFile / JSON) rather than hard-casting and throwing.
                $hostMap = @{}
                if ($Config.ContainsKey('HostMap')) {
                    $rawMap = $Config['HostMap']
                    if ($rawMap -is [System.Collections.IDictionary]) {
                        foreach ($k in $rawMap.Keys) { $hostMap[$k] = $rawMap[$k] }
                    } else {
                        Write-Warning "woscap: -Config HostMap is not a dictionary; ignoring it."
                    }
                }
                # ResolveDns may arrive as a bool or (from psd1/JSON config) a string; coerce so that
                #'false'/'0'/'no'/'off' are honored as false rather than truthy-non-empty strings.
                $resolveDns = $false
                if ($Config.ContainsKey('ResolveDns')) {
                    $resolveDns = ConvertTo-WoscapBool $Config['ResolveDns']
                }
                Join-WoscapFinding -Results @($CorrelateWith) -Findings @($imported) -HostMap $hostMap -ResolveDns:$resolveDns
            } else {
                $imported
            }
        }
    }
}

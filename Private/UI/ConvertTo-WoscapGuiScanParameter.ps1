function ConvertTo-WoscapGuiScanParameter {
    <#
        Pure helper: maps the GUI's input-control VALUES to a splat hashtable for
        Invoke-WoscapScan. No WinForms dependency. Empty/blank optional inputs are
        omitted so the cmdlet's own defaults apply (e.g. blank Targets = local scan).
        ThrottleLimit is omitted when it equals the cmdlet default.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $XccdfPath,
        [Parameter(Mandatory)] [string] $Benchmark,
        [string] $Targets = '',
        [string[]] $ProfilePath = @(),
        [pscredential] $Credential,
        [string] $ContentPath = '',
        [int] $ThrottleLimit = 0,
        [string] $JsonPath = ''
    )
    $splat = @{ XccdfPath = $XccdfPath; Benchmark = $Benchmark }

    $targetHosts = @($Targets -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($targetHosts.Count -gt 0) { $splat['ComputerName'] = $targetHosts }

    $profiles = @($ProfilePath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($profiles.Count -gt 0) { $splat['ProfilePath'] = $profiles }

    if ($Credential) { $splat['Credential'] = $Credential }
    if (-not [string]::IsNullOrWhiteSpace($ContentPath)) { $splat['ContentPath'] = $ContentPath }
    if ($PSBoundParameters.ContainsKey('ThrottleLimit') -and
        $ThrottleLimit -ne (Get-WoscapGuiScanDefault).ThrottleLimit) {
        $splat['ThrottleLimit'] = $ThrottleLimit
    }
    if (-not [string]::IsNullOrWhiteSpace($JsonPath)) { $splat['JsonPath'] = $JsonPath }

    $splat
}

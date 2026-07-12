function ConvertTo-WoscapGuiScanParameter {
    <#
        Pure helper: maps the GUI's input-control VALUES to a splat hashtable for
        Invoke-WoscapScan. No WinForms dependency. Empty/blank optional inputs are
        omitted so the cmdlet's own defaults apply (e.g. blank Targets = local scan).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $XccdfPath,
        [Parameter(Mandatory)] [string] $Benchmark,
        [string] $Targets = '',
        [string] $ProfilePath = '',
        [pscredential] $Credential
    )
    $splat = @{ XccdfPath = $XccdfPath; Benchmark = $Benchmark }

    $targetHosts = @($Targets -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($targetHosts.Count -gt 0) { $splat['ComputerName'] = $targetHosts }

    if (-not [string]::IsNullOrWhiteSpace($ProfilePath)) { $splat['ProfilePath'] = $ProfilePath }
    if ($Credential) { $splat['Credential'] = $Credential }

    $splat
}

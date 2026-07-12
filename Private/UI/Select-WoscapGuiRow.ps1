function Select-WoscapGuiRow {
    <#
        Pure presentation filter: narrows a RuleResult set by severity, status, and a
        case-insensitive substring matched against StigId + Title. 'All'/blank means no
        constraint. Never mutates the input; returns the filtered subset as an array.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Result,
        [string] $Severity = 'All',
        [string] $Status = 'All',
        [string] $Find = ''
    )
    $out = @($Result)
    if ($Severity -and $Severity -ne 'All') { $out = @($out | Where-Object { $_.Severity -eq $Severity }) }
    if ($Status   -and $Status   -ne 'All') { $out = @($out | Where-Object { $_.Status   -eq $Status }) }
    if (-not [string]::IsNullOrWhiteSpace($Find)) {
        $needle = $Find.Trim()
        $out = @($out | Where-Object { "$($_.StigId) $($_.Title)" -match [regex]::Escape($needle) })
    }
    $out
}

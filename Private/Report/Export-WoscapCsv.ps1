function Export-WoscapCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Result,
        [Parameter(Mandatory)] [string] $Path
    )
    $Result |
        Select-Object Host, Benchmark, BenchmarkVersion, StigId, GroupId, RuleId, Severity, Status,
            Title, Expected, Observed,
            @{ Name = 'Cci'; Expression = { ($_.Cci -join ';') } },
            FindingDetails, Comments |
        Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
}

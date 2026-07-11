function Invoke-WoscapScan {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $XccdfPath,
        [string] $Benchmark = 'Windows11',
        [string] $ContentPath,
        [string] $JsonPath,
        [switch] $Quiet
    )

    if (-not $ContentPath) {
        $ContentPath = Join-Path $script:WoscapModuleRoot (Join-Path 'Content' $Benchmark)
    }

    $rules = @(Import-Xccdf -Path $XccdfPath)
    $pack  = Import-ContentPack -Path $ContentPath
    $results = @(Invoke-CheckEval -Rules $rules -ContentPack $pack)

    if ($JsonPath) {
        ConvertTo-Json -InputObject $results -Depth 6 | Set-Content -LiteralPath $JsonPath -Encoding UTF8
    }

    if (-not $Quiet) {
        $byStatus = $results | Group-Object Status
        Write-Host ""
        Write-Host "woscap scan - $Benchmark - $($results.Count) rules"
        foreach ($g in ($byStatus | Sort-Object Name)) {
            Write-Host ("  {0,-16} {1}" -f $g.Name, $g.Count)
        }
        $openCat1 = @($results | Where-Object { $_.Status -eq 'Open' -and $_.Severity -eq 'high' }).Count
        Write-Host ("  Open CAT I:       {0}" -f $openCat1)
    }

    $results
}

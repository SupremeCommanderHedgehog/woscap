function Invoke-WoscapScan {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $XccdfPath,
        [string] $Benchmark = 'Windows11',
        [string] $ContentPath,
        [string[]] $ProfilePath,
        [string] $JsonPath,
        [switch] $Quiet
    )

    if (-not $ContentPath) {
        $ContentPath = Join-Path $script:WoscapModuleRoot (Join-Path 'Content' $Benchmark)
    }

    $rules = @(Import-Xccdf -Path $XccdfPath)
    $pack  = Import-ContentPack -Path $ContentPath
    $exceptions = @{}
    if ($ProfilePath) { $exceptions = Import-ExceptionProfile -Path $ProfilePath }
    $results = @(Invoke-CheckEval -Rules $rules -ContentPack $pack -ExceptionProfile $exceptions)

    if ($JsonPath) {
        Write-WoscapText -Text (ConvertTo-Json -InputObject $results -Depth 6) -Path $JsonPath
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
        $riskAccepted = @($results | Where-Object { $_.Status -eq 'Open' -and $_.Exception -and $_.Exception.Type -eq 'AcceptedRisk' }).Count
        Write-Host ("  of which risk-accepted: {0}" -f $riskAccepted)
    }

    $results
}

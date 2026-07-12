function Invoke-WoscapScan {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $XccdfPath,
        [string] $Benchmark = 'Windows11',
        [string] $ContentPath,
        [string[]] $ProfilePath,
        [string[]] $ComputerName,
        [pscredential] $Credential,
        [int] $ThrottleLimit = 8,
        [string] $JsonPath,
        [switch] $Quiet
    )

    # -Quiet means fully silent: suppress the engine's per-rule Write-Progress bar too,
    # not just the console summary. The GUI does NOT pass -Quiet, so its background
    # runspace still receives determinate progress records.
    if ($Quiet) { $ProgressPreference = 'SilentlyContinue' }

    if (-not $ContentPath) {
        $ContentPath = Join-Path $script:WoscapModuleRoot (Join-Path 'Content' $Benchmark)
    }
    if (-not (Test-Path -LiteralPath $ContentPath)) {
        throw "woscap: content pack path not found: $ContentPath"
    }

    $rules = @(Import-Xccdf -Path $XccdfPath)
    $exceptions = @{}
    if ($ProfilePath) { $exceptions = Import-ExceptionProfile -Path $ProfilePath }

    # Partition targets: local (in-process) vs remote (WinRM). localhost/self run
    # in-process; a mixed list scans BOTH. Omitted -ComputerName = local only.
    $localAliases = @('localhost', '.', '127.0.0.1', '::1', $env:COMPUTERNAME)
    $requested    = @($ComputerName | Where-Object { $_ } | Select-Object -Unique)
    $remoteHosts  = @($requested | Where-Object { $_ -notin $localAliases })
    $wantLocal    = ($requested.Count -eq 0) -or (@($requested | Where-Object { $_ -in $localAliases }).Count -gt 0)

    $collected = [System.Collections.Generic.List[object]]::new()
    if ($wantLocal) {
        $pack = Import-ContentPack -Path $ContentPath
        foreach ($r in @(Invoke-CheckEval -Rules $rules -ContentPack $pack -ExceptionProfile $exceptions)) { $collected.Add($r) }
    }
    if ($remoteHosts.Count -gt 0) {
        foreach ($r in @(Invoke-WoscapRemoteScan -ComputerName $remoteHosts -Credential $Credential -ThrottleLimit $ThrottleLimit `
            -Rules $rules -ExceptionProfile $exceptions -ModuleRoot $script:WoscapModuleRoot -Benchmark $Benchmark -ContentPath $ContentPath)) { $collected.Add($r) }
    }
    $results = @($collected.ToArray())

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

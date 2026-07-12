function Invoke-WoscapRemoteScan {
    <#
        Fans out a woscap scan across -ComputerName over WinRM. Opens sessions
        (native -ThrottleLimit), evaluates each via Invoke-WoscapSessionScan,
        and isolates failures: an unreachable host or a failed per-host scan
        yields exactly one synthetic Not_Reviewed RuleResult and never aborts
        the batch. Sessions are always removed. Returns the aggregated
        RuleResult[] (fail closed).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string[]] $ComputerName,
        [pscredential] $Credential,
        [int] $ThrottleLimit = 8,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rules,
        [hashtable] $ExceptionProfile = @{},
        [Parameter(Mandatory)] [string] $ModuleRoot,
        [Parameter(Mandatory)] [string] $Benchmark,
        [Parameter(Mandatory)] [string] $ContentPath
    )

    $results = [System.Collections.Generic.List[object]]::new()

    # 1. Open sessions with native throttling. Unreachable hosts simply do not
    #    come back in the session list (errors suppressed; detected by diff).
    $sessionParams = @{ ComputerName = $ComputerName; ThrottleLimit = $ThrottleLimit; ErrorAction = 'SilentlyContinue' }
    if ($Credential) { $sessionParams['Credential'] = $Credential }
    $sessions = @(New-PSSession @sessionParams)

    # 2. One synthetic Not_Reviewed result per host that failed to connect.
    $connected = @($sessions | ForEach-Object { $_.ComputerName })
    foreach ($bad in @($ComputerName | Where-Object { $_ -notin $connected })) {
        Write-Warning "woscap: host '$bad' unreachable (could not establish a PSSession over WinRM)."
        $results.Add((New-WoscapResult -Result 'Error' -ComputerName $bad -StigId '' -Severity 'medium' `
            -Title 'Host unreachable' -Benchmark $Benchmark `
            -FindingDetails "Host unreachable: could not establish a PSSession over WinRM."))
    }

    if ($sessions.Count -gt 0) {
        try {
            # 3. Ship + scan each session; isolate per-host failures.
            foreach ($s in $sessions) {
                try {
                    $hostResults = Invoke-WoscapSessionScan -Session $s -Rules $Rules -ExceptionProfile $ExceptionProfile `
                        -ModuleRoot $ModuleRoot -Benchmark $Benchmark -ContentPath $ContentPath
                    # A zero-rule host returns nothing; @($null) is a 1-element
                    # array holding $null, so filter nulls before aggregating to
                    # avoid injecting a bogus RuleResult that breaks reporters.
                    foreach ($r in @($hostResults)) { if ($null -ne $r) { $results.Add($r) } }
                } catch {
                    Write-Warning "woscap: scan of host '$($s.ComputerName)' failed: $_"
                    $results.Add((New-WoscapResult -Result 'Error' -ComputerName $s.ComputerName -StigId '' -Severity 'medium' `
                        -Title 'Remote scan error' -Benchmark $Benchmark `
                        -FindingDetails "Remote scan failed: $_"))
                }
            }
        } finally {
            # 4. Always tear down the sessions.
            Remove-WoscapSession -Session $sessions
        }
    }

    $results.ToArray()
}

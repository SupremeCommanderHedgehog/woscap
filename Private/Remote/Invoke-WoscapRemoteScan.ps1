function Invoke-WoscapRemoteScan {
    <#
        Fans a woscap scan across -ComputerName over WinRM. Opens sessions (native
        -ThrottleLimit), ships the curated module subset to each, then runs the
        engine on every host in ONE batched Invoke-Command (parallel fan-out).
        Fail-closed and per-host isolated: an unreachable host, a staging failure,
        or a per-host scan failure each yields exactly one synthetic Not_Reviewed
        and never aborts the batch. Remote temp dirs and sessions are always
        cleaned up. Returns the aggregated RuleResult[].
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
    $runId   = [guid]::NewGuid().ToString('N')

    # 1. Open sessions with native throttling. Unreachable hosts simply do not come
    #    back in the session list (errors suppressed; detected by normalized diff).
    $sessionParams = @{ ComputerName = $ComputerName; ThrottleLimit = $ThrottleLimit; ErrorAction = 'SilentlyContinue' }
    if ($Credential) { $sessionParams['Credential'] = $Credential }
    $sessions = @(New-PSSession @sessionParams)

    # 2. Robust reachability: a requested host is reachable if some open session
    #    names the same machine — matched case-insensitively, either exactly or as a
    #    short-name/FQDN pair (one name is the other's dot-delimited prefix). This is
    #    stricter than comparing bare first-labels, which would wrongly collapse
    #    distinct hosts sharing a leading label (e.g. web.east.corp vs web.west.corp);
    #    it also compares IP-address targets exactly (no dotted-octet collision).
    $sameHost = {
        param($a, $b)
        if ([string]::IsNullOrEmpty($a) -or [string]::IsNullOrEmpty($b)) { return $false }
        $a = $a.ToLowerInvariant(); $b = $b.ToLowerInvariant()
        $a -eq $b -or $a.StartsWith($b + '.') -or $b.StartsWith($a + '.')
    }
    $sessionNames = @($sessions | ForEach-Object { $_.ComputerName })
    foreach ($bad in @($ComputerName | Where-Object { $req = $_; (@($sessionNames | Where-Object { & $sameHost $req $_ })).Count -eq 0 })) {
        Write-Warning "woscap: host '$bad' unreachable (could not establish a PSSession over WinRM)."
        $results.Add((New-WoscapResult -Result 'Error' -ComputerName $bad -StigId '' -Severity 'medium' `
            -Title 'Host unreachable' -Benchmark $Benchmark `
            -FindingDetails "Host unreachable: could not establish a PSSession over WinRM."))
    }

    if ($sessions.Count -gt 0) {
        try {
            # 3. Ship the curated payload to each session; isolate staging failures.
            $scanSessions = [System.Collections.Generic.List[object]]::new()
            foreach ($s in $sessions) {
                try {
                    Push-WoscapScanPayload -Session $s -RunId $runId -ModuleRoot $ModuleRoot -ContentPath $ContentPath
                    $scanSessions.Add($s)
                } catch {
                    Write-Warning "woscap: staging host '$($s.ComputerName)' failed: $_"
                    $results.Add((New-WoscapResult -Result 'Error' -ComputerName $s.ComputerName -StigId '' -Severity 'medium' `
                        -Title 'Remote scan error' -Benchmark $Benchmark `
                        -FindingDetails "Remote staging failed: $_"))
                }
            }

            # 4. One batched, parallel scan over the successfully-staged sessions.
            if ($scanSessions.Count -gt 0) {
                $scan = Invoke-WoscapBatchedScan -Session $scanSessions.ToArray() -ThrottleLimit $ThrottleLimit `
                    -RunId $runId -Rules $Rules -ExceptionProfile $ExceptionProfile

                # Real results (filter the zero-rule no-op $null so reporters don't choke).
                foreach ($r in @($scan.Results)) { if ($null -ne $r) { $results.Add($r) } }

                # One synthetic Not_Reviewed per host whose scan threw.
                foreach ($h in @($scan.Failures.Keys)) {
                    Write-Warning "woscap: scan of host '$h' failed: $($scan.Failures[$h])"
                    $results.Add((New-WoscapResult -Result 'Error' -ComputerName $h -StigId '' -Severity 'medium' `
                        -Title 'Remote scan error' -Benchmark $Benchmark `
                        -FindingDetails "Remote scan failed: $($scan.Failures[$h])"))
                }
            }
        } finally {
            # 5. Always tear down remote temp dirs (all connected hosts) and sessions.
            Remove-WoscapScanPayload -Session $sessions -RunId $runId
            Remove-WoscapSession -Session $sessions
        }
    }

    $results.ToArray()
}

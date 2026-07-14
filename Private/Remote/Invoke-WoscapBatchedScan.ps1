function Invoke-WoscapBatchedScan {
    <#
        Thin, untested-by-design seam over a single batched Invoke-Command. Runs
        the woscap engine on EVERY session in parallel (native -ThrottleLimit),
        importing the already-shipped module from $env:TEMP\woscap_<RunId>. Returns
        a { Results; Failures } shape so the caller's fail-closed aggregation stays
        unit-testable without -ErrorVariable gymnastics:
          Results  = object[]  (engine RuleResults across all reachable hosts)
          Failures = @{ '<host>' = '<message>' }  (one entry per host that threw)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Session,
        [int] $ThrottleLimit = 8,
        [Parameter(Mandatory)] [string] $RunId,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rules,
        [hashtable] $ExceptionProfile = @{}
    )

    $scanErr = @()
    $out = Invoke-Command -Session $Session -ThrottleLimit $ThrottleLimit `
        -ArgumentList $RunId, $Rules, $ExceptionProfile `
        -ErrorAction Continue -ErrorVariable +scanErr -ScriptBlock {
            param($runId, $rules, $exceptions)
            $root     = Join-Path $env:TEMP ('woscap_' + $runId)
            $manifest = Join-Path $root 'woscap.psd1'
            $packPath = Join-Path $root '_content'
            Import-Module $manifest -Force
            & (Get-Module woscap) {
                param($packPath, $rules, $exceptions)
                # Zero-rule host is a clean no-op: skip pack import + engine, return nothing.
                if (@($rules).Count -eq 0) { return }
                $pack = Import-ContentPack -Path $packPath
                Invoke-CheckEval -Rules $rules -ContentPack $pack `
                    -ExceptionProfile $exceptions -ComputerName $env:COMPUTERNAME
            } $packPath $rules $exceptions
        }

    # Partition per-host failures by originating host. A remoting error record
    # carries the host in OriginInfo.PSComputerName.
    $failures = @{}
    foreach ($e in @($scanErr)) {
        $h = if ($e.OriginInfo) { $e.OriginInfo.PSComputerName } else { $null }
        if ([string]::IsNullOrEmpty($h)) { $h = '(unknown remote host)' }
        $failures[$h] = $e.ToString()
    }

    [pscustomobject]@{ Results = @($out); Failures = $failures }
}

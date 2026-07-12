function Resolve-WoscapGuiCompletion {
    <#
        Decides how the GUI should report a finished scan, distinguishing a partial
        success from a real failure so a single unreachable host in a multi-target
        scan is not presented as a total failure.

        Returns [pscustomobject] @{ Kind; Message; Count } where Kind is:
          None    - no errors; the scan succeeded cleanly.
          Warning - results were delivered AND non-terminating errors occurred
                    (e.g. one host down among several). Surface non-modally.
          Error   - a real failure: either a terminating error, or errors with
                    NO results to show.

        Both the Error stream (genuine non-terminating errors) and the Warning stream
        (how the remote fan-out reports a failed/unreachable host, plus ignored-exception
        and invalid-override notices) count as issues -- a host failure surfaces only on
        the Warning stream, so reading errors alone would miss the very case this exists for.

        On the terminating path, the accumulated issue detail (the per-rule / per-host text
        that explains the root cause) is joined onto the terminating message so it is not lost.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [object[]] $Results,
        [object[]] $ErrorRecords,
        [object[]] $WarningRecords,
        [string] $TerminatingError
    )
    $issues = @(@($ErrorRecords) + @($WarningRecords) | Where-Object { $_ })
    $detail = ($issues | ForEach-Object { $_.ToString() }) -join "`n"

    if ($TerminatingError) {
        $message = if ($detail) { "$TerminatingError`n$detail" } else { $TerminatingError }
        return [pscustomobject]@{ Kind = 'Error'; Message = $message; Count = $issues.Count }
    }
    if ($issues.Count -eq 0) {
        return [pscustomobject]@{ Kind = 'None'; Message = ''; Count = 0 }
    }
    if (@($Results).Count -gt 0) {
        return [pscustomobject]@{ Kind = 'Warning'; Message = $detail; Count = $issues.Count }
    }
    return [pscustomobject]@{ Kind = 'Error'; Message = $detail; Count = $issues.Count }
}

function Remove-WoscapScanPayload {
    <#
        Thin, untested-by-design seam: batched cleanup of the per-run temp dir on
        every session. Remove-Item runs target-side (in the remote scriptblock),
        not on the audit host — see ReadOnly.Tests.ps1 whitelist. Best-effort:
        a missing dir on a partially-staged host is tolerated.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Session,
        [Parameter(Mandatory)] [string] $RunId
    )
    Invoke-Command -Session $Session -ArgumentList $RunId -ErrorAction SilentlyContinue -ScriptBlock {
        param($runId)
        Remove-Item -Path (Join-Path $env:TEMP ('woscap_' + $runId)) -Recurse -Force -ErrorAction SilentlyContinue
    }
}

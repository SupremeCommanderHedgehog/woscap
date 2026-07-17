function Remove-WoscapBenchmark {
    <#
    .SYNOPSIS
        Removes cached STIG content from the operator-local content cache.
    .DESCRIPTION
        Without -Revision, removes the entire <Benchmark> subtree from the cache.
        With -Revision, removes only that one revision directory. Gated by
        ShouldProcess (ConfirmImpact High) — prompts by default; use -WhatIf to
        preview and -Confirm:$false to skip the prompt. Operates only on the
        operator-local cache; it never touches the audited endpoint.
    .PARAMETER Benchmark
        The benchmark name (cache subtree) to prune. Mandatory — there is no
        argless whole-cache wipe.
    .PARAMETER Revision
        Optional. When given, only <cacheRoot>\<Benchmark>\<Revision> is removed.
    .PARAMETER Destination
        Optional cache-root override; defaults to the standard content cache root.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Benchmark,
        [string] $Revision,
        [string] $Destination
    )

    # Guard both operator-supplied segments BEFORE touching disk — the same guard the reader
    # (Get-WoscapBenchmark) and producer (Save-WoscapStigContent) apply — so a crafted '..\'
    # cannot escape the cache root under -LiteralPath normalization.
    Assert-WoscapSafePathSegment -Segment $Benchmark -Kind 'benchmark name'
    if ($Revision) { Assert-WoscapSafePathSegment -Segment $Revision -Kind 'STIG revision' }

    $cacheRoot = Get-WoscapContentCacheRoot -Destination $Destination
    $benchDir  = Join-Path $cacheRoot $Benchmark
    $target    = if ($Revision) { Join-Path $benchDir $Revision } else { $benchDir }

    if (-not (Test-Path -LiteralPath $target)) {
        Write-Warning "woscap: nothing to remove at '$target'."
        return
    }

    if ($PSCmdlet.ShouldProcess($target, 'Remove cached STIG content')) {
        Remove-Item -LiteralPath $target -Recurse -Force
        $target
    }
}

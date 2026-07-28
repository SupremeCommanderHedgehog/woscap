function Clear-WoscapReadCache {
    <#
    .SYNOPSIS
        Drop every memoized reading. Called at the start of each scan so
        back-to-back scans in one session never see a stale reading.
    #>
    [CmdletBinding()]
    param()
    $script:WoscapReadCache = @{}
}

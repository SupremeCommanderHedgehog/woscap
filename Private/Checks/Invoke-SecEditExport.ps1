function Invoke-SecEditExportRaw {
    <#
    .SYNOPSIS
        Launch secedit.exe and return the exported policy text. Uncached.
    #>
    [CmdletBinding()]
    param()
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        $null = & secedit.exe /export /cfg $tmp /quiet 2>$null
        $content = Get-Content -Path $tmp -Raw
        if ([string]::IsNullOrWhiteSpace($content)) {
            throw 'secedit export produced no output (administrator privileges may be required to read the security policy).'
        }
        $content
    } finally {
        Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-SecEditExport {
    <#
    .SYNOPSIS
        Exported security policy text, memoized for the life of one scan.
    .DESCRIPTION
        Get-SecEditSetting and Get-UserRight both read through this, and a
        Windows 11 scan makes dozens of such reads. Without memoization each
        one launches secedit.exe afresh.
    #>
    [CmdletBinding()]
    param()
    Get-WoscapCachedValue -Key 'secedit:export' -Producer { Invoke-SecEditExportRaw }
}

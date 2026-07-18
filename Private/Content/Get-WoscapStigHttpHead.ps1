function Get-WoscapStigHttpHead {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Uri)

    # Cheap HEAD pre-check for the download short-circuit: learn the current ETag /
    # Last-Modified without pulling the archive body. Fails open — any error returns
    # $null so the caller falls through to a normal GET. The short-circuit is an
    # optimization and must never block a real download.
    try {
        $resp = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing -ErrorAction Stop
    } catch {
        return $null
    }
    if (-not $resp -or -not $resp.Headers) { return $null }

    # Header values are a plain string on PowerShell 7 but can be string[] on Windows
    # PowerShell 5.1; normalize to a single trimmed string (first element, '' when absent).
    $read = {
        param($name)
        $v = $resp.Headers[$name]
        if ($null -eq $v) { return '' }
        if ($v -is [array]) { if ($v.Count -eq 0) { return '' } else { $v = $v[0] } }
        [string] $v
    }
    [pscustomobject]@{
        ETag         = (& $read 'ETag')
        LastModified = (& $read 'Last-Modified')
    }
}

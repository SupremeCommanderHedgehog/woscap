function Get-WoscapStigManifest {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([string] $Path)

    # Read-only: loads the bundled benchmark->URL pointer manifest (or an explicit -Path).
    # Returns an empty hashtable when the file is missing or unreadable, so callers can
    # treat "no manifest" and "benchmark not listed" the same way. Never writes to disk.
    # This is a best-effort pointer file, NOT DISA content; -Url always overrides it in
    # Resolve-WoscapStigUrl.
    $manifestPath = if ($Path) { $Path } else { Join-Path $script:WoscapModuleRoot (Join-Path 'Content' 'stig-sources.psd1') }
    if (-not (Test-Path -LiteralPath $manifestPath)) { return @{} }

    try {
        $data = Import-PowerShellDataFile -LiteralPath $manifestPath
    } catch {
        Write-Warning "woscap: could not read STIG manifest '$manifestPath': $_"
        return @{}
    }
    if ($data -is [hashtable]) { return $data }
    return @{}
}

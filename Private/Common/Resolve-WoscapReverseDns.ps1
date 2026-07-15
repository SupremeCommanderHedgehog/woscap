function Resolve-WoscapReverseDns {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Ip)

    if ([string]::IsNullOrWhiteSpace($Ip)) { return $null }

    try {
        $entry = [System.Net.Dns]::GetHostEntry($Ip)
        if ($entry -and $entry.HostName) { return $entry.HostName }
        return $null
    } catch {
        Write-Verbose "woscap: reverse-DNS for '$Ip' failed: $_"
        return $null
    }
}

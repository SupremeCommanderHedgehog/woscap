function Resolve-WoscapHostKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyString()] [string] $HostName,
        [hashtable] $HostMap = @{},
        [switch] $ResolveDns
    )
    if ([string]::IsNullOrEmpty($HostName)) { return $HostName }

    if ($HostMap -and $HostMap.ContainsKey($HostName)) { return [string] $HostMap[$HostName] }

    # Require a dot (IPv4) or colon (IPv6) before trusting TryParse — otherwise a bare
    # integer like '16843009' parses as an IP and a legitimately-named host gets reverse-resolved.
    if ($ResolveDns -and $HostName -match '[.:]') {
        if ([System.Net.IPAddress]::TryParse($HostName, [ref] $null)) {
            $resolved = Resolve-WoscapReverseDns -Ip $HostName
            if ($resolved) { return $resolved }
        }
    }

    return $HostName
}

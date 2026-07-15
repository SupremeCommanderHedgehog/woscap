function Join-WoscapFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [hashtable] $HostMap = @{},
        [switch] $ResolveDns
    )

    $links = [System.Collections.Generic.List[object]]::new()

    # Memoize host-key resolution by raw host string so duplicate hosts (and, under
    # -ResolveDns, duplicate blocking reverse-DNS lookups) collapse to one resolution each.
    $keyCache = @{}
    $resolveKey = {
        param($h)
        $s = [string] $h
        if (-not $keyCache.ContainsKey($s)) {
            $keyCache[$s] = Resolve-WoscapHostKey -HostName $s -HostMap $HostMap -ResolveDns:$ResolveDns
        }
        $keyCache[$s]
    }

    # Precompute each rule's canonical host key AND its CCI list once (both invariant across findings).
    $ruleInfo = @($Results | ForEach-Object {
        [pscustomobject]@{
            Rule = $_
            Key  = & $resolveKey (Get-WoscapObjectProperty $_ 'Host')
            Cci  = @(Get-WoscapObjectProperty $_ 'Cci') | Where-Object { $_ }
        }
    })

    foreach ($finding in $Findings) {
        $findingIds = @(Get-WoscapObjectProperty $finding 'Cve') + @(Get-WoscapObjectProperty $finding 'Cce') + @(Get-WoscapObjectProperty $finding 'Cci') | Where-Object { $_ }
        $findingKey = & $resolveKey (Get-WoscapObjectProperty $finding 'Host')
        foreach ($ri in $ruleInfo) {
            # Name-equivalence (case-insensitive exact or short-name/FQDN prefix), not raw ==; null/empty hosts never match.
            if (-not (Test-WoscapSameHost $ri.Key $findingKey)) { continue }
            $match = @($findingIds | Where-Object { $_ -in $ri.Cci }) | Select-Object -First 1
            if ($match) {
                $links.Add([pscustomobject]@{
                    Host      = $findingKey
                    RuleId    = Get-WoscapObjectProperty $ri.Rule 'RuleId'
                    FindingId = Get-WoscapObjectProperty $finding 'Id'
                    MatchedOn = $match
                })
            }
        }
    }

    [pscustomobject]@{
        Results  = $Results
        Findings = $Findings
        Links    = $links.ToArray()
    }
}

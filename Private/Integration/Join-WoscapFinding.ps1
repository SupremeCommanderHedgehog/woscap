function Join-WoscapFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Results,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings
    )

    $links = [System.Collections.Generic.List[object]]::new()

    foreach ($finding in $Findings) {
        $findingIds = @(Get-WoscapObjectProperty $finding 'Cve') + @(Get-WoscapObjectProperty $finding 'Cce') + @(Get-WoscapObjectProperty $finding 'Cci') | Where-Object { $_ }
        $findingHost = Get-WoscapObjectProperty $finding 'Host'
        foreach ($rule in $Results) {
            if ((Get-WoscapObjectProperty $rule 'Host') -ne $findingHost) { continue }
            $ruleCci = @(Get-WoscapObjectProperty $rule 'Cci') | Where-Object { $_ }
            $match = @($findingIds | Where-Object { $_ -in $ruleCci }) | Select-Object -First 1
            if ($match) {
                $links.Add([pscustomobject]@{
                    Host      = $findingHost
                    RuleId    = Get-WoscapObjectProperty $rule 'RuleId'
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

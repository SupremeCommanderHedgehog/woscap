function Get-WoscapComplianceMetric {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Result)

    # Read Status/Severity/Exception tolerantly so foreign or projected objects
    # (which may lack these members) don't throw under StrictMode.
    $open = @($Result | Where-Object { (Get-WoscapObjectProperty $_ 'Status') -eq 'Open' })
    $na   = @($Result | Where-Object { (Get-WoscapObjectProperty $_ 'Status') -eq 'Not_Applicable' })
    $pass = @($Result | Where-Object { (Get-WoscapObjectProperty $_ 'Status') -eq 'NotAFinding' })
    $evaluated = $Result.Count - $na.Count
    # An empty scan or an all-Not_Applicable scan has nothing to attest: report 0,
    # never 100. A false-green dashboard is worse than an honest zero.
    $compliance = if ($evaluated -gt 0) { ($pass.Count / $evaluated) * 100 } else { 0 }

    $exceptions = @($Result | Where-Object { Get-WoscapObjectProperty $_ 'Exception' })
    $riskAccepted = @($exceptions | Where-Object {
            $ex = Get-WoscapObjectProperty $_ 'Exception'
            $exType = if ($ex) { Get-WoscapObjectProperty $ex 'Type' }
            $exType -eq 'AcceptedRisk'
        })

    @{
        'woscap.open.cat1'                = @($open | Where-Object { (Get-WoscapObjectProperty $_ 'Severity') -eq 'high' }).Count
        'woscap.open.cat2'                = @($open | Where-Object { (Get-WoscapObjectProperty $_ 'Severity') -eq 'medium' }).Count
        'woscap.open.cat3'                = @($open | Where-Object { (Get-WoscapObjectProperty $_ 'Severity') -eq 'low' }).Count
        'woscap.findings.total'           = $Result.Count
        'woscap.compliance.pct'           = [math]::Round($compliance, 2)
        'woscap.exceptions.count'         = $exceptions.Count
        'woscap.exceptions.riskaccepted'  = $riskAccepted.Count
    }
}

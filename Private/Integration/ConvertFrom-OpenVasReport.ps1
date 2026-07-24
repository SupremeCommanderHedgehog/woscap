function ConvertFrom-OpenVasReport {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path')] [string] $Path,
        [Parameter(Mandatory, ParameterSetName = 'Xml')]  [string] $Xml
    )

    $src = if ($PSCmdlet.ParameterSetName -eq 'Path') { "'$Path'" } else { 'in-memory report' }
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            [xml] $doc = Get-Content -LiteralPath $Path -Raw
        } else {
            [xml] $doc = $Xml
        }
    } catch {
        Write-Warning "woscap: could not parse OpenVAS report ${src}: $_"; return @()
    }

    $results = $doc.SelectNodes('//result')
    if (-not $results -or $results.Count -eq 0) {
        Write-Warning "woscap: OpenVAS report ${src} contained no <result> nodes."; return @()
    }

    # Node access is via XPath (SelectSingleNode / SelectNodes) rather than the
    # dotted DOM shortcuts: the module runs under Set-StrictMode -Version Latest,
    # where accessing an ABSENT XML child element/attribute throws
    # PropertyNotFoundException. XPath returns $null / an empty list for missing
    # nodes without tripping strict mode, so a sparse-but-parseable report still
    # yields findings instead of aborting the import (fail-warn-only contract).
    $getText = { param($Node, $XPath) $n = $Node.SelectSingleNode($XPath); if ($n) { $n.InnerText } else { $null } }

    foreach ($r in $results) {
        $nvt  = $r.SelectSingleNode('nvt')
        $refs = @($r.SelectNodes('nvt/refs/ref'))
        $cve = @($refs | Where-Object { $_.GetAttribute('type') -eq 'cve' } | ForEach-Object { $_.GetAttribute('id') })
        $cce = @($refs | Where-Object { $_.GetAttribute('type') -eq 'cce' } | ForEach-Object { $_.GetAttribute('id') })
        $cci = @($refs | Where-Object { $_.GetAttribute('type') -eq 'cci' } | ForEach-Object { $_.GetAttribute('id') })

        [pscustomobject]@{
            Host        = (& $getText $r 'host')
            Source      = 'OpenVAS'
            Id          = if ($nvt) { $nvt.GetAttribute('oid') } else { $null }
            Name        = if ($nvt) { (& $getText $nvt 'name') } else { $null }
            Severity    = ConvertTo-WoscapThreatSeverity -Threat ([string](& $getText $r 'threat'))
            Cvss        = [string](& $getText $r 'severity')
            Cve         = $cve
            Cce         = $cce
            Cci         = $cci
            Port        = (& $getText $r 'port')
            Description = (& $getText $r 'description')
        }
    }
}

function ConvertTo-WoscapThreatSeverity {
    param([string] $Threat)
    switch -Regex ($Threat) {
        '^(High|Critical)$' { 'high';   break }
        '^Medium$'          { 'medium'; break }
        '^(Low|Log)$'       { 'low';    break }
        default             { 'medium' }
    }
}

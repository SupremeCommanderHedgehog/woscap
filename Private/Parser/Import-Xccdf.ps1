function Import-Xccdf {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "XCCDF file not found: $Path"
    }
    try {
        [xml]$xml = Get-Content -LiteralPath $Path -Raw
    } catch {
        throw "Failed to parse XML from '$Path': $_"
    }
    if ($xml.DocumentElement.LocalName -ne 'Benchmark') {
        throw "Not an XCCDF Benchmark document: root element is '$($xml.DocumentElement.LocalName)'."
    }

    $nsUri = $xml.DocumentElement.NamespaceURI
    $nsm = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $nsm.AddNamespace('c', $nsUri)

    $benchTitleNode = $xml.SelectSingleNode('/c:Benchmark/c:title', $nsm)
    $benchTitle = if ($benchTitleNode) { $benchTitleNode.InnerText } else { '' }
    $benchVerNode = $xml.SelectSingleNode('/c:Benchmark/c:version', $nsm)
    $benchVer = if ($benchVerNode) { $benchVerNode.InnerText } else { $null }

    foreach ($group in $xml.SelectNodes('//c:Group', $nsm)) {
        $rule = $group.SelectSingleNode('c:Rule', $nsm)
        if (-not $rule) { continue }

        $groupTitleNode = $group.SelectSingleNode('c:title', $nsm)
        $versionNode = $rule.SelectSingleNode('c:version', $nsm)
        $titleNode   = $rule.SelectSingleNode('c:title', $nsm)
        $descNode    = $rule.SelectSingleNode('c:description', $nsm)
        $checkNode   = $rule.SelectSingleNode('c:check/c:check-content', $nsm)
        $fixNode     = $rule.SelectSingleNode('c:fixtext', $nsm)
        $cci = @($rule.SelectNodes('c:ident', $nsm) | ForEach-Object { $_.InnerText })

        [pscustomobject]@{
            GroupId          = $group.id
            GroupTitle       = if ($groupTitleNode) { $groupTitleNode.InnerText } else { '' }
            RuleId           = $rule.id
            StigId           = if ($versionNode) { $versionNode.InnerText } else { $null }
            Severity         = $rule.severity
            Title            = if ($titleNode) { $titleNode.InnerText } else { '' }
            Discussion       = if ($descNode)  { $descNode.InnerText }  else { '' }
            CheckText        = if ($checkNode) { $checkNode.InnerText } else { '' }
            FixText          = if ($fixNode)   { $fixNode.InnerText }   else { '' }
            Cci              = $cci
            Benchmark        = $benchTitle
            BenchmarkVersion = $benchVer
        }
    }
}

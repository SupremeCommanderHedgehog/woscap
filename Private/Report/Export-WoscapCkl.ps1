function Export-WoscapCkl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Result,
        [Parameter(Mandatory)] [string] $Path
    )
    if (@($Result).Count -eq 0) { throw 'Export-WoscapCkl: no results to export.' }
    $first = $Result[0]

    function Esc([object] $Text) { [System.Security.SecurityElement]::Escape([string]$Text) }
    function StigData([string] $Attr, [object] $Data) {
        "        <STIG_DATA><VULN_ATTRIBUTE>$Attr</VULN_ATTRIBUTE><ATTRIBUTE_DATA>$(Esc $Data)</ATTRIBUTE_DATA></STIG_DATA>"
    }

    $version = if ($first.BenchmarkVersion) { [string]$first.BenchmarkVersion } else { '1' }
    $stigId  = ([string]$first.Benchmark -replace '\s', '_')

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
    [void]$sb.AppendLine('<CHECKLIST>')
    [void]$sb.AppendLine('  <ASSET>')
    [void]$sb.AppendLine('    <ROLE>None</ROLE>')
    [void]$sb.AppendLine('    <ASSET_TYPE>Computing</ASSET_TYPE>')
    [void]$sb.AppendLine("    <HOST_NAME>$(Esc $first.Host)</HOST_NAME>")
    [void]$sb.AppendLine('    <HOST_IP></HOST_IP>')
    [void]$sb.AppendLine('    <HOST_MAC></HOST_MAC>')
    [void]$sb.AppendLine('    <HOST_FQDN></HOST_FQDN>')
    [void]$sb.AppendLine('    <TARGET_COMMENT></TARGET_COMMENT>')
    [void]$sb.AppendLine('    <TECH_AREA></TECH_AREA>')
    [void]$sb.AppendLine('    <TARGET_KEY></TARGET_KEY>')
    [void]$sb.AppendLine('    <WEB_OR_DATABASE>false</WEB_OR_DATABASE>')
    [void]$sb.AppendLine('    <WEB_DB_SITE></WEB_DB_SITE>')
    [void]$sb.AppendLine('    <WEB_DB_INSTANCE></WEB_DB_INSTANCE>')
    [void]$sb.AppendLine('  </ASSET>')
    [void]$sb.AppendLine('  <STIGS>')
    [void]$sb.AppendLine('    <iSTIG>')
    [void]$sb.AppendLine('      <STIG_INFO>')
    [void]$sb.AppendLine("        <SI_DATA><SID_NAME>version</SID_NAME><SID_DATA>$(Esc $version)</SID_DATA></SI_DATA>")
    [void]$sb.AppendLine("        <SI_DATA><SID_NAME>stigid</SID_NAME><SID_DATA>$(Esc $stigId)</SID_DATA></SI_DATA>")
    [void]$sb.AppendLine("        <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>$(Esc $first.Benchmark)</SID_DATA></SI_DATA>")
    [void]$sb.AppendLine("        <SI_DATA><SID_NAME>releaseinfo</SID_NAME><SID_DATA>$(Esc "Version: $version")</SID_DATA></SI_DATA>")
    [void]$sb.AppendLine('      </STIG_INFO>')

    foreach ($r in $Result) {
        [void]$sb.AppendLine('      <VULN>')
        [void]$sb.AppendLine((StigData 'Vuln_Num'     $r.GroupId))
        [void]$sb.AppendLine((StigData 'Severity'     $r.Severity))
        [void]$sb.AppendLine((StigData 'Rule_ID'      $r.RuleId))
        [void]$sb.AppendLine((StigData 'Rule_Ver'     $r.StigId))
        [void]$sb.AppendLine((StigData 'Rule_Title'   $r.Title))
        [void]$sb.AppendLine((StigData 'Vuln_Discuss' $r.Discussion))
        [void]$sb.AppendLine((StigData 'Check_Content' $r.CheckText))
        [void]$sb.AppendLine((StigData 'Fix_Text'     $r.FixText))
        foreach ($cci in @($r.Cci)) {
            [void]$sb.AppendLine((StigData 'CCI_REF' $cci))
        }
        [void]$sb.AppendLine("        <STATUS>$(Esc $r.Status)</STATUS>")
        [void]$sb.AppendLine("        <FINDING_DETAILS>$(Esc $r.FindingDetails)</FINDING_DETAILS>")
        [void]$sb.AppendLine("        <COMMENTS>$(Esc $r.Comments)</COMMENTS>")
        [void]$sb.AppendLine('        <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>')
        [void]$sb.AppendLine('        <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>')
        [void]$sb.AppendLine('      </VULN>')
    }

    [void]$sb.AppendLine('    </iSTIG>')
    [void]$sb.AppendLine('  </STIGS>')
    [void]$sb.AppendLine('</CHECKLIST>')

    Write-WoscapText -Text $sb.ToString() -Path $Path
}

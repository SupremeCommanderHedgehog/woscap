@{
    'Get-Targets' = {
        param($Source, $Config)
        $group = if ($Config -and $Config.ContainsKey('Group')) { [string]$Config.Group } else { $null }
        if ($group) { ConvertFrom-AnsibleInventory -Path $Source -Group $group }
        else        { ConvertFrom-AnsibleInventory -Path $Source }
    }
    'New-Remediation' = {
        param($Result, [string] $Path, $Config)
        $benchmark   = if ($Config -and $Config.ContainsKey('Benchmark'))   { [string]$Config.Benchmark }   else { 'Windows11' }
        $contentPath = if ($Config -and $Config.ContainsKey('ContentPath')) { [string]$Config.ContentPath } else { Join-Path $script:WoscapModuleRoot (Join-Path 'Content' $benchmark) }
        $pack = Import-ContentPack -Path $contentPath
        $open = @($Result | Where-Object { (Get-WoscapObjectProperty $_ 'Status') -eq 'Open' })
        $text = ConvertTo-AnsiblePlaybook -FailedRule $open -ContentPack $pack
        # BOM-less UTF-8: a UTF-8 BOM breaks ansible-playbook's YAML parser on PS 5.1.
        Write-WoscapText -Text $text -Path $Path
        $Path
    }
    'Export-Findings' = {
        param($Result, $Config)
        $factsPath = if ($Config -and $Config.ContainsKey('FactsPath')) { [string]$Config.FactsPath } else { Join-Path ([System.IO.Path]::GetTempPath()) 'woscap_facts.json' }
        $facts = @{ woscap_findings = @($Result) }
        # BOM-less UTF-8, consistent across PS 5.1 and 7.
        Write-WoscapText -Text ($facts | ConvertTo-Json -Depth 6) -Path $factsPath
        [pscustomobject]@{ FactsPath = $factsPath; Count = @($Result).Count }
    }
}

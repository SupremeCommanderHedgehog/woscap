# Spec invariant 8.4 (#29): every Registry descriptor's required kind must agree
# with the registry type DISA states for that rule. Uses the licensed local
# XCCDFs under STIG/, so it is skipped on CI and wherever an archive is missing.
BeforeDiscovery {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $archives = [ordered]@{
        Windows11         = 'U_MS_Windows_11_V2R11_STIG.zip'
        Edge              = 'U_MS_Edge_V2R5_STIG.zip'
        Chrome            = 'U_Google_Chrome_V2R11_STIG.zip'
        Firefox           = 'U_MOZ_Firefox_V6R9_STIG.zip'
        DefenderAntivirus = 'U_MS_Defender_Antivirus_V2R10_STIG.zip'
        DefenderFirewall  = 'U_MS_Windows_Defender_Firewall_V2R2_STIG.zip'
        AcrobatReader     = 'U_Adobe_Acrobat_Reader_DC_Continuous_V2R1_STIG.zip'
    }
    $script:auditCases = foreach ($pack in $archives.Keys) {
        $zip = Join-Path $script:RepoRoot "STIG/$($archives[$pack])"
        @{ Pack = $pack; Zip = $zip; Skip = [bool]$env:CI -or -not (Test-Path -LiteralPath $zip) }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    function Read-AuditCheckContent {
        param([string] $Zip)
        $archive = [System.IO.Compression.ZipFile]::OpenRead($Zip)
        try {
            $entry = @($archive.Entries | Where-Object { $_.FullName -like '*Manual-xccdf.xml' })[0]
            $reader = New-Object System.IO.StreamReader($entry.Open())
            try { $xml = [xml]$reader.ReadToEnd() } finally { $reader.Dispose() }
        } finally { $archive.Dispose() }
        $map = @{}
        foreach ($rule in $xml.SelectNodes("//*[local-name()='Rule']")) {
            $version = $rule.SelectSingleNode("*[local-name()='version']").InnerText
            $content = $rule.SelectSingleNode(".//*[local-name()='check-content']")
            if ($version -and $content) { $map[$version] = $content.InnerText }
        }
        $map
    }

    # Returns the REG_ type DISA states for Name, 'none' when the rule states no
    # type, or 'ambiguous' when several types are stated and Name does not pick one.
    function Get-AuditDisaType {
        param([string] $Text, [string] $Name)
        $hits = @(
            [regex]::Matches($Text, '(?i)(?:Value\s+)?Type:\s*(REG_[A-Z_]+)')
            [regex]::Matches($Text, '(?i)\b(REG_[A-Z_]+)\s*=')
        ) | ForEach-Object { [pscustomobject]@{ Index = $_.Index; Type = $_.Groups[1].Value.ToUpperInvariant() } } |
            Sort-Object Index
        $types = @($hits | ForEach-Object { $_.Type } | Sort-Object -Unique)
        if ($types.Count -eq 0) { return 'none' }
        if ($types.Count -eq 1) { return $types[0] }
        # Several types: take the first type stated after each mention of the value name.
        $nameHits = [regex]::Matches($Text, '(?i)(?<![A-Za-z0-9_])' + [regex]::Escape($Name) + '(?![A-Za-z0-9_])')
        $picked = @($(foreach ($n in $nameHits) {
            $next = @($hits | Where-Object { $_.Index -gt $n.Index -and $_.Index - $n.Index -lt 300 })
            if ($next.Count -gt 0) { $next[0].Type }
        }) | Sort-Object -Unique)
        if ($picked.Count -eq 1) { return $picked[0] }
        'ambiguous'
    }

    function Get-AuditRegistryDescriptor {
        param($Descriptor, [string] $Context)
        if ($Descriptor -isnot [hashtable] -or -not $Descriptor.ContainsKey('Type')) { return }
        if ($Descriptor.Type -eq 'Registry') { [pscustomobject]@{ Context = $Context; Descriptor = $Descriptor } }
        if ($Descriptor.ContainsKey('Checks')) {
            $i = 0
            foreach ($c in @($Descriptor.Checks)) { Get-AuditRegistryDescriptor $c "$Context.Checks[$i]"; $i++ }
        }
        if ($Descriptor.ContainsKey('Evidence')) { Get-AuditRegistryDescriptor $Descriptor.Evidence "$Context.Evidence" }
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Registry descriptor kinds agree with DISA-stated registry types' {
    It '<Pack>: every stated REG_ type is an allowed kind' -ForEach $script:auditCases -Skip:$Skip {
        $kindOf = @{ REG_DWORD = 'DWord'; REG_QWORD = 'QWord'; REG_SZ = 'String'; REG_EXPAND_SZ = 'ExpandString'; REG_MULTI_SZ = 'MultiString' }
        $checkText = Read-AuditCheckContent -Zip $Zip
        $packDir = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "Content/$Pack"
        $data = InModuleScope woscap -Parameters @{ D = $packDir } { param($D) Import-ContentPack -Path $D -WarningAction SilentlyContinue }

        $mismatch = New-Object System.Collections.Generic.List[string]
        $unstated = New-Object System.Collections.Generic.List[string]
        $checked = 0
        foreach ($key in @($data.Keys | Sort-Object)) {
            foreach ($item in @(Get-AuditRegistryDescriptor $data[$key] $key)) {
                $d = $item.Descriptor
                $required = InModuleScope woscap -Parameters @{ D = $d } { param($D) Get-WoscapRequiredRegKind -Descriptor $D }
                # Operator-less evidence is reported, never judged, so no kind applies.
                if ($required.Error -and -not $d.ContainsKey('Operator') -and -not $d.ContainsKey('Kind')) { continue }
                if (-not $checkText.ContainsKey($key)) { $unstated.Add("$($item.Context) (rule not in XCCDF)"); continue }
                $disa = Get-AuditDisaType -Text $checkText[$key] -Name ([string]$d.Name)
                if ($disa -in @('none', 'ambiguous')) { $unstated.Add("$($item.Context) [$($d.Name)]: $disa"); continue }
                $checked++
                if (-not $kindOf.ContainsKey($disa)) { $mismatch.Add("$($item.Context) [$($d.Name)]: DISA $disa has no supported kind"); continue }
                if ($required.Error) { $mismatch.Add("$($item.Context) [$($d.Name)]: $($required.Error)"); continue }
                if ($required.Kinds -ne '*' -and @($required.Kinds) -notcontains $kindOf[$disa]) {
                    $mismatch.Add("$($item.Context) [$($d.Name)]: DISA $disa, descriptor requires $(@($required.Kinds) -join '/')")
                }
            }
        }
        Write-Host "$Pack registry kind audit: $checked checked, $($mismatch.Count) mismatched, $($unstated.Count) without a stated type"
        foreach ($u in $unstated) { Write-Host "  no stated type: $u" }
        @($mismatch) | Should -BeNullOrEmpty
    }
}

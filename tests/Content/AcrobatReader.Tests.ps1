BeforeDiscovery {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:ZipPath = Join-Path $script:RepoRoot 'STIG/U_Adobe_Acrobat_Reader_DC_Continuous_V2R1_STIG.zip'
    $script:NoXccdf = -not (Test-Path -LiteralPath $script:ZipPath)

    # The rule spec the behavioural tests hold the pack to; reconciled with the XCCDF where present.
    $f = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'
    $af = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'
    $simple = @(
        # Id, FeatureLockDown subkey, Name, Expected
        ,@('ARDC-CN-000005', '', 'bEnhancedSecurityStandalone', 1)
        ,@('ARDC-CN-000010', '', 'bEnhancedSecurityInBrowser', 1)
        ,@('ARDC-CN-000015', '', 'bProtectedMode', 1)
        ,@('ARDC-CN-000020', '', 'iProtectedView', 2)
        ,@('ARDC-CN-000025', 'cDefaultLaunchURLPerms', 'iURLPerms', 1)
        ,@('ARDC-CN-000030', 'cDefaultLaunchURLPerms', 'iUnknownURLPerms', 3)
        ,@('ARDC-CN-000035', '', 'iFileAttachmentPerms', 1)
        ,@('ARDC-CN-000045', '', 'bEnableFlash', 0)
        ,@('ARDC-CN-000050', '', 'bDisablePDFHandlerSwitching', 1)
        ,@('ARDC-CN-000055', 'cCloud', 'bAdobeSendPluginToggle', 1)
        ,@('ARDC-CN-000060', 'cServices', 'bToggleAdobeDocumentServices', 1)
        ,@('ARDC-CN-000065', 'cServices', 'bTogglePrefsSync', 1)
        ,@('ARDC-CN-000075', 'cServices', 'bToggleWebConnectors', 1)
        ,@('ARDC-CN-000080', '', 'bAcroSuppressUpsell', 1)
        ,@('ARDC-CN-000085', 'cServices', 'bToggleAdobeSign', 1)
        ,@('ARDC-CN-000090', 'cWebmailProfiles', 'bDisableWebmail', 1)
        ,@('ARDC-CN-000100', 'cSharePoint', 'bDisableSharePointFeatures', 1)
        ,@('ARDC-CN-000115', 'cWelcomeScreen', 'bShowWelcomeScreen', 0)
        ,@('ARDC-CN-000120', 'cServices', 'bUpdater', 0)
        ,@('ARDC-CN-000315', '', 'bDisableTrustedFolders', 1)
        ,@('ARDC-CN-000320', '', 'bDisableTrustedSites', 1)
    )
    # Bad values on both sides of Expected, so an eq mutated to ge, le or ne fails a test.
    $script:Simple = foreach ($r in $simple) {
        $sub = if ($r[1]) { "\$($r[1])" } else { '' }
        @{ Id = $r[0]; Path = "$f$sub"; AcrobatPath = "$af$sub"; Name = $r[2]; Expected = $r[3]; Bad = @(($r[3] - 1), ($r[3] + 1)) }
    }

    $script:Hkcu = @(
        @{ Id = 'ARDC-CN-000330'; Path = 'HKCU:\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\cEUTLDownload'; Name = 'bLoadSettingsFromURL'; Expected = 0 }
        @{ Id = 'ARDC-CN-000335'; Path = 'HKCU:\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\cAdobeDownload'; Name = 'bLoadSettingsFromURL'; Expected = 0 }
        @{ Id = 'ARDC-CN-000345'; Path = 'HKCU:\Software\Adobe\Acrobat Reader\DC\AVGeneral'; Name = 'bFIPSMode'; Expected = 1 }
    )
    $script:OptedOut = @('ARDC-CN-000025', 'ARDC-CN-000100')
    $script:AllIds = @($script:Simple.Id) + @($script:Hkcu.Id) + @('ARDC-CN-000070', 'ARDC-CN-000340')
}

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:PackPath = Join-Path $script:RepoRoot 'Content/AcrobatReader'
    Import-Module (Join-Path $script:RepoRoot 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'AcrobatReader pack shape' {
    It 'has exactly the 26 spec rules' -ForEach @(@{ Ids = $script:AllIds }) {
        $pack = InModuleScope woscap -Parameters @{ P = $script:PackPath } { Import-ContentPack -Path $P -WarningAction SilentlyContinue }
        @($pack.Keys | Sort-Object) | Should -Be @($Ids | Sort-Object)
        $pack.Count | Should -Be 26
    }

    It 'loads without schema warnings' {
        InModuleScope woscap -Parameters @{ P = $script:PackPath } {
            $warnings = $null
            $null = Import-ContentPack -Path $P -WarningVariable warnings -WarningAction SilentlyContinue
            @($warnings) | Should -BeNullOrEmpty
        }
    }

    It 'never treats an absent value as compliant' {
        $pack = InModuleScope woscap -Parameters @{ P = $script:PackPath } { Import-ContentPack -Path $P -WarningAction SilentlyContinue }
        $walk = { param($d) $d; foreach ($c in @($d.Checks)) { if ($c -is [hashtable]) { & $walk $c } } }
        foreach ($d in @($pack.Values | ForEach-Object { & $walk $_ })) { $d.ContainsKey('AbsentIsPass') | Should -BeFalse }
    }

    # Every check depends on detection, so no single write provably passes on every host.
    It 'reports every rule Manual in remediation, keeping the opt-out reasons' -ForEach @(@{ OptedOut = $script:OptedOut }) {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; OptedOut = $OptedOut } {
            param($P, $OptedOut)
            $pack = Import-ContentPack -Path $P -WarningAction SilentlyContinue
            $rules = @($pack.Keys | ForEach-Object { [pscustomobject]@{ StigId = $_; Title = $_; Status = 'Open' } })
            $plan = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            $plan.Count | Should -Be 26
            @($plan | Where-Object { $_.Automatable }) | Should -BeNullOrEmpty
            foreach ($id in $OptedOut) { ($plan | Where-Object StigId -eq $id).ManualReason | Should -Match 'cannot detect' }
        }
    }

    It '<Id> requires DISA''s value, and the same value under the Adobe Acrobat root when the unified app is detected' -ForEach $script:Simple {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; Rule = $_ } {
            param($P, $Rule)
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)[$Rule.Id]
            $sig = { param($c) "$($c['Type'])|$($c['Path'])|$($c['Name'])|$($c['Operator'])|$($c['Expected'])" }
            $d.Type | Should -Be 'All'
            @($d.Checks).Count | Should -Be 2
            & $sig $d.Checks[0] | Should -Be "Registry|$($Rule.Path)|$($Rule.Name)|eq|$($Rule.Expected)"
            $d.Checks[1].Type | Should -Be 'Any'
            & $sig $d.Checks[1].Checks[0] | Should -Be "Registry|$($Rule.AcrobatPath)|$($Rule.Name)|eq|$($Rule.Expected)"
            $nat = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'
            $wow = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'
            @($d.Checks[1].Checks[1].Checks | ForEach-Object { & $sig $_ }) | Should -Be @(
                "Path|$nat||eq|False", "Path|$wow||eq|False",
                "Registry|$nat|Is64BitProduct|exists|False", "Registry|$wow|Is64BitProduct|exists|False")
        }
    }
}

# Detection: an Adobe Acrobat\DC\Installer key in either view, probed with a fail-closed read.
Describe 'AcrobatReader FeatureLockDown rules' {
    It '<Id> passes and fails on both roots by detection state' -ForEach $script:Simple {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; Rule = $_ } {
            param($P, $Rule)
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)[$Rule.Id]
            $nat = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'
            $wow = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'
            $r = "$($Rule.Path)|$($Rule.Name)"; $a = "$($Rule.AcrobatPath)|$($Rule.Name)"
            $v = $Rule.Expected
            $unread = New-WoscapUnreadable -Reason 'test: access denied'
            $script:reg = @{}; $script:paths = @()
            Mock Get-RegValue { $k = "$Path|$Name"; if ($script:reg.ContainsKey($k)) { $script:reg[$k] } else { $null } }
            Mock Test-PathPresence { $Path -in $script:paths }

            # Paths present, registry values, expected result.
            $cases = [System.Collections.Generic.List[object]]::new()
            $cases.Add(@(@(), @{ $r = $v }, 'Pass'))
            foreach ($b in $Rule.Bad) { $cases.Add(@(@(), @{ $r = $b; $a = $v }, 'Fail')) }
            $cases.Add(@(@(), @{ $a = $v }, 'Fail'))
            $cases.Add(@(@(), @{ $r = $unread }, 'Error'))
            $cases.Add(@(@($nat), @{ $r = $v; $a = $v; "$nat|Is64BitProduct" = 1 }, 'Pass'))
            $cases.Add(@(@($nat), @{ $r = $v; "$nat|Is64BitProduct" = 1 }, 'Fail'))
            $cases.Add(@(@($nat), @{ $a = $v; "$nat|Is64BitProduct" = 1 }, 'Fail'))
            foreach ($b in $Rule.Bad) { $cases.Add(@(@($nat), @{ $r = $v; $a = $b }, 'Fail')) }
            $cases.Add(@(@($nat), @{ $r = $v; $a = $unread }, 'Error'))
            $cases.Add(@(@($wow), @{ $r = $v }, 'Fail'))
            $cases.Add(@(@($wow), @{ $r = $v; $a = $v }, 'Pass'))
            $cases.Add(@(@(), @{ $r = $v; "$wow|Is64BitProduct" = 1 }, 'Fail'))
            $cases.Add(@(@(), @{ $r = $v; "$nat|Is64BitProduct" = $unread }, 'Error'))
            $cases.Add(@(@(), @{ $r = $v; "$wow|Is64BitProduct" = $unread }, 'Error'))

            $miss = foreach ($c in $cases) {
                $script:paths = @($c[0]); $script:reg = $c[1]
                $got = (Test-Descriptor -Descriptor $d).Result
                if ($got -ne $c[2]) { "paths [$($c[0] -join ',')] reg [$(($c[1].Keys | ForEach-Object { "$_=$($c[1][$_])" }) -join ',')]: expected $($c[2]), got $got" }
            }
            @($miss) | Should -BeNullOrEmpty
        }
    }

    It 'treats an unreadable detection path as not Pass' {
        InModuleScope woscap -Parameters @{ P = $script:PackPath } {
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)['ARDC-CN-000005']
            Mock Get-RegValue { $null }
            Mock Get-RegValue { 1 } -ParameterFilter { $Path -eq 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown' }
            Mock Test-PathPresence { New-WoscapUnreadable -Reason 'test: access denied' }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Error'
        }
    }
}

Describe 'AcrobatReader repair installation (ARDC-CN-000070)' {
    It 'reads the view DISA names for the OS bitness, plus the unified app Installer key when detected' {
        InModuleScope woscap -Parameters @{ P = $script:PackPath } {
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)['ARDC-CN-000070']
            $wow = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer|DisableMaintenance'
            $nat = 'HKLM:\Software\Adobe\Acrobat Reader\DC\Installer|DisableMaintenance'
            $ukey = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'
            $uni = "$ukey|DisableMaintenance"
            $u64 = "$ukey|Is64BitProduct"
            $script:arch = $null; $script:reg = @{}; $script:paths = @()
            Mock Get-CimSetting { $script:arch }
            Mock Get-RegValue { $k = "$Path|$Name"; if ($script:reg.ContainsKey($k)) { $script:reg[$k] } else { $null } }
            Mock Test-PathPresence { $Path -in $script:paths }
            $unread = New-WoscapUnreadable -Reason 'test: access denied'
            $cases = @(
                ,@('64-bit', @(), @{ $wow = 1 }, 'Pass')
                ,@('64-bit', @(), @{ $wow = 0 }, 'Fail')
                ,@('64-bit', @(), @{ $wow = 2 }, 'Fail')
                ,@('64-bit', @(), @{ $nat = 1 }, 'Fail')
                ,@('64-bit', @(), @{ $wow = 0; $nat = 1 }, 'Fail')
                ,@('64-bit', @(), @{}, 'Fail')
                ,@('32-bit', @(), @{ $nat = 1 }, 'Pass')
                ,@('32-bit', @(), @{ $wow = 1 }, 'Fail')
                ,@('', @(), @{ $wow = 1; $nat = 1 }, 'Fail')
                ,@('64-bit', @($ukey), @{ $wow = 1; $uni = 1; $u64 = 1 }, 'Pass')
                ,@('64-bit', @($ukey), @{ $wow = 1; $u64 = 1 }, 'Fail')
                ,@('64-bit', @($ukey), @{ $uni = 1; $u64 = 1 }, 'Fail')
                ,@('64-bit', @($ukey), @{ $wow = 1; $uni = 0 }, 'Fail')
                ,@('64-bit', @($ukey), @{ $wow = 1; $uni = 2 }, 'Fail')
                ,@('64-bit', @(), @{ $wow = 1; $u64 = $unread }, 'Error')
                ,@('64-bit', @(), @{ $wow = $unread }, 'Error')
                ,@($unread, @(), @{ $wow = 1 }, 'Error')
            )
            $miss = foreach ($c in $cases) {
                $script:arch = $c[0]; $script:paths = @($c[1]); $script:reg = $c[2]
                $got = (Test-Descriptor -Descriptor $d).Result
                if ($got -ne $c[3]) { "arch '$($c[0])' paths [$($c[1] -join ',')] reg [$(($c[2].Keys | ForEach-Object { "$_=$($c[2][$_])" }) -join ',')]: expected $($c[3]), got $got" }
            }
            @($miss) | Should -BeNullOrEmpty
        }
    }
}

Describe 'AcrobatReader HKCU and manual rules' {
    It '<Id> is Manual and reports both per-user roots for the scanning account' -ForEach $script:Hkcu {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; Rule = $_ } {
            param($P, $Rule)
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)[$Rule.Id]
            $acro = $Rule.Path -replace '\\Acrobat Reader\\', '\Adobe Acrobat\'
            $d.Type | Should -Be 'Manual'
            @($d.Evidence.Checks | ForEach-Object { "$($_.Path)|$($_.Name)" }) | Should -Be @("$($Rule.Path)|$($Rule.Name)", "$acro|$($Rule.Name)")
            $d.Question | Should -Match ([regex]::Escape("$($Rule.Name) = $($Rule.Expected) (REG_DWORD)"))
            $d.Question | Should -Match ([regex]::Escape(($Rule.Path -replace '^HKCU:', 'HKCU')))
            $d.Question | Should -Match ([regex]::Escape(($acro -replace '^HKCU:', 'HKCU')))
            $d.Question | Should -Match 'absence is a finding'
            Mock Get-RegValue { $null }
            Mock Get-RegValue { 'READER' } -ParameterFilter { $Path -eq $Rule.Path -and $Name -eq $Rule.Name }
            Mock Get-RegValue { 'ACROBAT' } -ParameterFilter { $Path -eq $acro -and $Name -eq $Rule.Name }
            $r = Test-Descriptor -Descriptor $d
            $r.Result | Should -Be 'NotReviewed'
            "$($r.Observed)" | Should -Be 'READER; ACROBAT'
        }
    }

    It 'ARDC-CN-000340 (latest updates) is Manual' {
        InModuleScope woscap -Parameters @{ P = $script:PackPath } {
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)['ARDC-CN-000340']
            $d.Type | Should -Be 'Manual'
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'NotReviewed'
        }
    }
}

# Skipped where the licensed archive is absent (CI). Ties the spec above to DISA's text.
Describe 'AcrobatReader spec reconciles with the V2R1 XCCDF' -Skip:$script:NoXccdf {
    BeforeAll {
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead((Join-Path $script:RepoRoot 'STIG/U_Adobe_Acrobat_Reader_DC_Continuous_V2R1_STIG.zip'))
        try {
            $entry = @($zip.Entries | Where-Object { $_.FullName -like '*Manual-xccdf.xml' })[0]
            $reader = [System.IO.StreamReader]::new($entry.Open())
            try { $xml = [xml]$reader.ReadToEnd() } finally { $reader.Dispose() }
        } finally { $zip.Dispose() }
        $script:Rules = @{}
        foreach ($g in $xml.Benchmark.Group) { $script:Rules[[string]$g.Rule.version] = [string]$g.Rule.check.'check-content' }
        # Exact key line, then the Name/Type/Value block DISA states.
        $script:Needs = {
            param($Text, $Hive, $Path, $Name, $Expected)
            $key = $Path -replace '^HK(LM|CU):', $Hive
            $Text | Should -Match ('(?m)' + [regex]::Escape($key) + '[ \t]*\r?$')
            $Text | Should -Match ('Value Name: ' + [regex]::Escape($Name) + '\s*\r?\nType: REG_DWORD\s*\r?\nValue: ' + $Expected + '\s')
        }
    }

    It 'pack keys are exactly the 26 XCCDF rule versions' {
        $pack = InModuleScope woscap -Parameters @{ P = $script:PackPath } { Import-ContentPack -Path $P -WarningAction SilentlyContinue }
        $script:Rules.Count | Should -Be 26
        @($pack.Keys | Sort-Object) | Should -Be @($script:Rules.Keys | Sort-Object)
    }

    It '<Id> check-content states the HKLM key, value and that absence is a finding' -ForEach $script:Simple {
        $text = $script:Rules[$Id]
        & $script:Needs $text 'HKEY_LOCAL_MACHINE' $Path $Name $Expected
        $text | Should -Match 'or does not exist, (then )?this is a finding'
        $text | Should -Not -Match 'HKEY_CURRENT_USER|Wow6432Node'
    }

    It '<Id> check-content is an HKCU rule' -ForEach $script:Hkcu {
        & $script:Needs $script:Rules[$Id] 'HKEY_CURRENT_USER' $Path $Name $Expected
    }

    It 'ARDC-CN-000070 names the native key for 32 bit and Wow6432Node for 64 bit' {
        $text = $script:Rules['ARDC-CN-000070']
        $text | Should -Match 'For 32 bit:\s*\r?\nHKEY_LOCAL_MACHINE\\Software\\Adobe\\Acrobat Reader\\DC\\Installer\s*\r?\n'
        $text | Should -Match 'For 64 bit:\s*\r?\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Adobe\\Acrobat Reader\\DC\\Installer\s*\r?\n'
        $text | Should -Match 'Value Name: DisableMaintenance\s*\r?\nType: REG_DWORD\s*\r?\nValue: 1\s'
        $text | Should -Match 'or does not exist, (then )?this is a finding'
    }

    It 'opted-out rules carry the NA or risk-acceptance condition woscap cannot observe' {
        $script:Rules['ARDC-CN-000025'] | Should -Match 'documented ISSO risk acceptance'
        $script:Rules['ARDC-CN-000100'] | Should -Match 'approved DoD SharePoint Server, this is NA'
        $script:Rules['ARDC-CN-000340'] | Should -Match 'latest security-related software updates'
    }
}

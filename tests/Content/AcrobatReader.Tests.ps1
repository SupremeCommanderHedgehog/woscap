BeforeDiscovery {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:ZipPath = Join-Path $script:RepoRoot 'STIG/U_Adobe_Acrobat_Reader_DC_Continuous_V2R1_STIG.zip'
    $script:NoXccdf = -not (Test-Path -LiteralPath $script:ZipPath)

    # The rule spec the behavioural tests hold the pack to; reconciled with the XCCDF where present.
    $f = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'
    $simple = @(
        # Id, Path, Name, Expected, Bad
        ,@('ARDC-CN-000005', $f, 'bEnhancedSecurityStandalone', 1, @(0, 2))
        ,@('ARDC-CN-000010', $f, 'bEnhancedSecurityInBrowser', 1, @(0))
        ,@('ARDC-CN-000015', $f, 'bProtectedMode', 1, @(0))
        ,@('ARDC-CN-000020', $f, 'iProtectedView', 2, @(0, 1))
        ,@('ARDC-CN-000025', "$f\cDefaultLaunchURLPerms", 'iURLPerms', 1, @(0, 2))
        ,@('ARDC-CN-000030', "$f\cDefaultLaunchURLPerms", 'iUnknownURLPerms', 3, @(1, 2))
        ,@('ARDC-CN-000035', $f, 'iFileAttachmentPerms', 1, @(0))
        ,@('ARDC-CN-000045', $f, 'bEnableFlash', 0, @(1))
        ,@('ARDC-CN-000050', $f, 'bDisablePDFHandlerSwitching', 1, @(0))
        ,@('ARDC-CN-000055', "$f\cCloud", 'bAdobeSendPluginToggle', 1, @(0))
        ,@('ARDC-CN-000060', "$f\cServices", 'bToggleAdobeDocumentServices', 1, @(0))
        ,@('ARDC-CN-000065', "$f\cServices", 'bTogglePrefsSync', 1, @(0))
        ,@('ARDC-CN-000075', "$f\cServices", 'bToggleWebConnectors', 1, @(0))
        ,@('ARDC-CN-000080', $f, 'bAcroSuppressUpsell', 1, @(0))
        ,@('ARDC-CN-000085', "$f\cServices", 'bToggleAdobeSign', 1, @(0))
        ,@('ARDC-CN-000090', "$f\cWebmailProfiles", 'bDisableWebmail', 1, @(0))
        ,@('ARDC-CN-000100', "$f\cSharePoint", 'bDisableSharePointFeatures', 1, @(0))
        ,@('ARDC-CN-000115', "$f\cWelcomeScreen", 'bShowWelcomeScreen', 0, @(1))
        ,@('ARDC-CN-000120', "$f\cServices", 'bUpdater', 0, @(1))
        ,@('ARDC-CN-000315', $f, 'bDisableTrustedFolders', 1, @(0))
        ,@('ARDC-CN-000320', $f, 'bDisableTrustedSites', 1, @(0))
    )
    $script:Simple = foreach ($r in $simple) { @{ Id = $r[0]; Path = $r[1]; Name = $r[2]; Expected = $r[3]; Bad = $r[4] } }

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
        $flat = foreach ($d in $pack.Values) { $d; @($d.Checks); @($d.Checks).Checks }
        foreach ($d in @($flat | Where-Object { $_ -is [hashtable] })) { $d.ContainsKey('AbsentIsPass') | Should -BeFalse }
    }

    It 'automates only the HKLM single-value rules that are not opted out' -ForEach @(@{ OptedOut = $script:OptedOut }) {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; OptedOut = $OptedOut } {
            param($P, $OptedOut)
            $pack = Import-ContentPack -Path $P -WarningAction SilentlyContinue
            $rules = @($pack.Keys | ForEach-Object { [pscustomobject]@{ StigId = $_; Title = $_; Status = 'Open' } })
            $plan = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            $auto = @($plan | Where-Object { $_.Automatable })
            foreach ($a in $auto) {
                $desc = $pack[$a.StigId]
                $desc.Type | Should -Be 'Registry'
                $a.Registry.Kind | Should -Be 'dword'
                $a.Registry.Path | Should -Match '^HKLM:\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown(\\|$)'
            }
            foreach ($id in @($OptedOut) + 'ARDC-CN-000070') {
                $a = $plan | Where-Object StigId -eq $id
                $a.Automatable | Should -BeFalse
                if ($id -ne 'ARDC-CN-000070') { $a.ManualReason | Should -Match 'cannot detect' }
            }
            $auto.Count | Should -Be 19
        }
    }
}

# Representative states per rule: good passes, bad fails, absent fails, unreadable is Error.
Describe 'AcrobatReader HKLM policy rules' {
    It '<Id> passes <Expected>, fails bad, absent and unreadable' -ForEach $script:Simple {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; Rule = $_ } {
            param($P, $Rule)
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)[$Rule.Id]
            $d.Type | Should -Be 'Registry'
            $d.Path | Should -Be $Rule.Path
            $d.Name | Should -Be $Rule.Name
            $script:val = $null
            $script:key = "$($Rule.Path)|$($Rule.Name)"
            Mock Get-RegValue { if ("$Path|$Name" -eq $script:key) { $script:val } else { $null } }

            $got = [ordered]@{}
            $script:val = $Rule.Expected; $got['good'] = (Test-Descriptor -Descriptor $d).Result
            foreach ($v in $Rule.Bad) { $script:val = $v; $got["bad '$v'"] = (Test-Descriptor -Descriptor $d).Result }
            $script:val = $null; $got['absent'] = (Test-Descriptor -Descriptor $d).Result
            $script:val = New-WoscapUnreadable -Reason 'test: access denied'; $got['unreadable'] = (Test-Descriptor -Descriptor $d).Result

            $bad = foreach ($k in $got.Keys) {
                $want = if ($k -eq 'good') { 'Pass' } elseif ($k -eq 'unreadable') { 'Error' } else { 'Fail' }
                if ($got[$k] -ne $want) { "${k}: expected $want, got $($got[$k])" }
            }
            @($bad) | Should -BeNullOrEmpty
        }
    }
}

Describe 'AcrobatReader repair installation (ARDC-CN-000070)' {
    It 'reads only the registry view DISA names for the OS bitness' {
        InModuleScope woscap -Parameters @{ P = $script:PackPath } {
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)['ARDC-CN-000070']
            $wow = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer'
            $nat = 'HKLM:\Software\Adobe\Acrobat Reader\DC\Installer'
            $script:arch = $null; $script:reg = @{}
            Mock Get-CimSetting { $script:arch }
            Mock Get-RegValue { if ($Name -eq 'DisableMaintenance' -and $script:reg.ContainsKey($Path)) { $script:reg[$Path] } else { $null } }
            $unread = New-WoscapUnreadable -Reason 'test: access denied'
            $cases = @(
                ,@('64-bit', @{ $wow = 1 }, 'Pass')
                ,@('64-bit', @{ $nat = 1 }, 'Fail')
                ,@('64-bit', @{ $wow = 0; $nat = 1 }, 'Fail')
                ,@('64-bit', @{}, 'Fail')
                ,@('32-bit', @{ $nat = 1 }, 'Pass')
                ,@('32-bit', @{ $wow = 1 }, 'Fail')
                ,@('', @{ $wow = 1; $nat = 1 }, 'Fail')
                ,@('64-bit', @{ $wow = $unread }, 'Error')
                ,@($unread, @{ $wow = 1 }, 'Error')
            )
            $miss = foreach ($c in $cases) {
                $script:arch = $c[0]; $script:reg = $c[1]
                $got = (Test-Descriptor -Descriptor $d).Result
                if ($got -ne $c[2]) { "arch '$($c[0])' reg [$(($c[1].Keys | ForEach-Object { "$_=$($c[1][$_])" }) -join ',')]: expected $($c[2]), got $got" }
            }
            @($miss) | Should -BeNullOrEmpty
        }
    }
}

Describe 'AcrobatReader HKCU and manual rules' {
    It '<Id> is Manual and reports the scanning account HKCU value as evidence' -ForEach $script:Hkcu {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; Rule = $_ } {
            param($P, $Rule)
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)[$Rule.Id]
            $d.Type | Should -Be 'Manual'
            $d.Evidence.Path | Should -Be $Rule.Path
            $d.Evidence.Name | Should -Be $Rule.Name
            $d.Question | Should -Match ([regex]::Escape("$($Rule.Name) = $($Rule.Expected) (REG_DWORD)"))
            $d.Question | Should -Match ([regex]::Escape(($Rule.Path -replace '^HKCU:', 'HKCU')))
            $d.Question | Should -Match 'absence is a finding'
            Mock Get-RegValue { 'EVIDENCE' } -ParameterFilter { $Path -eq $Rule.Path -and $Name -eq $Rule.Name }
            $r = Test-Descriptor -Descriptor $d
            $r.Result | Should -Be 'NotReviewed'
            "$($r.Observed)" | Should -Be 'EVIDENCE'
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

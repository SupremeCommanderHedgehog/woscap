BeforeDiscovery {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:ZipPath = Join-Path $script:RepoRoot 'STIG/U_MOZ_Firefox_V6R9_STIG.zip'
    $script:NoXccdf = -not (Test-Path -LiteralPath $script:ZipPath)

    # The rule spec the behavioural tests hold the pack to. Disa holds patterns the
    # V6R9 check-content must contain, re-checked against the XCCDF where present.
    $f = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
    $simple = @(
        # Id, Path, Name, Good, Bad, Disa patterns
        ,@('FFOX-00-000002', $f, 'SSLVersionMin', @('tls1.2', 'tls1.3'), @('tls1', 'tls1.1', 'TLS1.2', 'tls1.2 ', "tls1.2`n", 'xtls1.3', 1), @('"SSLVersionMin"', '"tls1\.2" or "tls1\.3"'))
        ,@('FFOX-00-000005', $f, 'ExtensionUpdate', @(0), @(1), @('"ExtensionUpdate"', 'Value is not "false"'))
        ,@('FFOX-00-000007', $f, 'DisableFormHistory', @(1), @(0), @('"DisableFormHistory"', 'Value is not "true"'))
        ,@('FFOX-00-000008', $f, 'PasswordManagerEnabled', @(0), @(1), @('"PasswordManagerEnabled"', 'Value is not "false"'))
        ,@('FFOX-00-000013', "$f\InstallAddonsPermission", 'Default', @(0), @(1), @('"InstallAddonsPermission"', 'not "Default" "false"'))
        ,@('FFOX-00-000014', $f, 'DisableTelemetry', @(1), @(0), @('"DisableTelemetry"', 'Value is not "true"'))
        ,@('FFOX-00-000015', $f, 'DisableDeveloperTools', @(1), @(0), @('"DisableDeveloperTools"', 'Value is not "true"'))
        ,@('FFOX-00-000018', $f, 'DisableForgetButton', @(1), @(0), @('"DisableForgetButton"', 'Value is not "true"'))
        ,@('FFOX-00-000019', $f, 'DisablePrivateBrowsing', @(1), @(0), @('"DisablePrivateBrowsing"', 'Value is not "true"'))
        ,@('FFOX-00-000020', $f, 'SearchSuggestEnabled', @(0), @(1), @('"SearchSuggestEnabled"', 'Value is not "false"'))
        ,@('FFOX-00-000021', "$f\Permissions\Autoplay", 'Default', @('block-audio-video'), @('block-audio', 'allow-audio-video', 'Block-Audio-Video', 'block-audio-video2'), @('"Permissions"', '"Autoplay" with a value of "Default" and "Block-audio-video"'))
        ,@('FFOX-00-000022', $f, 'NetworkPrediction', @(0), @(1), @('"NetworkPrediction"', 'Value is not "false"'))
        ,@('FFOX-00-000023', "$f\EnableTrackingProtection", 'Fingerprinting', @(1), @(0), @('"EnableTrackingProtection"', '"Fingerprinting"\s+with a value of "true"'))
        ,@('FFOX-00-000024', "$f\EnableTrackingProtection", 'Cryptomining', @(1), @(0), @('"EnableTrackingProtection"', '"Cryptomining"\s+with a value of "true"'))
        ,@('FFOX-00-000027', "$f\DisabledCiphers", 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', @(1), @(0), @('"DisabledCiphers"', '"TLS_RSA_WITH_3DES_EDE_CBC_SHA"\s+with a value of\s+"true"'))
        ,@('FFOX-00-000028', "$f\UserMessaging", 'ExtensionRecommendations', @(0), @(1), @('"UserMessaging"', '"ExtensionRecommendations" with a value of "false"'))
        ,@('FFOX-00-000033', "$f\DNSOverHTTPS", 'Enabled', @(0), @(1), @('"DNSOverHTTPS"', '"Enabled" with a value of "false"'))
        ,@('FFOX-00-000034', $f, 'DisableFirefoxAccounts', @(1), @(0), @('"DisableFirefoxAccounts"', 'Value is not "true"'))
        ,@('FFOX-00-000036', $f, 'DisableFeedbackCommands', @(1), @(0), @('"DisableFeedbackCommands"', 'Value is not "true"'))
        ,@('FFOX-00-000039', $f, 'DisableFirefoxStudies', @(1), @(0), @('"DisableFirefoxStudies"', 'a value of "true"'))
    )
    $script:Simple = foreach ($r in $simple) { @{ Id = $r[0]; Path = $r[1]; Name = $r[2]; Good = $r[3]; Bad = $r[4]; Disa = $r[5] } }

    # Nested-object policies: every named value under one subkey must hold.
    $script:Composite = @(
        @{ Id = 'FFOX-00-000009'; Path = "$f\PopupBlocking"; Expect = [ordered]@{ Default = 1; Locked = 1 }
           Disa = @('"PopupBlocking"', '"Default" "true"', '"Locked" "true"') }
        @{ Id = 'FFOX-00-000017'; Path = "$f\SanitizeOnShutdown"
           Expect = [ordered]@{ Cache = 0; Cookies = 0; Downloads = 0; FormData = 0; Sessions = 0; History = 0; OfflineApps = 0; SiteSettings = 0; Locked = 1 }
           Disa = @('"SanitizeOnShutdown"', [regex]::Escape('{"Cache":false,"Cookies":false,"Downloads":false,"FormData":false,"Sessions":false,"History":false,"OfflineApps":false,"SiteSettings":false,"Locked":true}')) }
        @{ Id = 'FFOX-00-000029'; Path = "$f\FirefoxHome"
           Expect = [ordered]@{ Search = 0; TopSites = 0; SponsoredTopSites = 0; Pocket = 0; SponsoredPocket = 0; Highlights = 0; Snippets = 0; Locked = 1 }
           Disa = @('"FirefoxHome"', '"Search" with a value of "false"', '"TopSites" with a value of "false"', '"SponsoredTopSites" with a value of "false"',
                    '"Pocket" with a value of "false"', '"SponsoredPocket" with a value of "false"', '"Highlights" with a value of "false"',
                    '"Snippets" with a value of "false"', '"Locked" with a value of "true"') }
        @{ Id = 'FFOX-00-000037'; Path = "$f\EncryptedMediaExtensions"; Expect = [ordered]@{ Enabled = 0; Locked = 1 }
           Disa = @('"EncryptedMediaExtensions"', '"Enabled" set to "false"', '"Locked" set to "true"') }
    )

    # Preferences rules: Manual, with the pref name DISA requires.
    $script:Manual = @(
        @{ Id = 'FFOX-00-000003'; Pref = 'security.default_personal_cert' }
        @{ Id = 'FFOX-00-000004'; Pref = 'browser.search.update' }
        @{ Id = 'FFOX-00-000010'; Pref = 'dom.disable_window_move_resize' }
        @{ Id = 'FFOX-00-000011'; Pref = 'dom.disable_window_flip' }
        @{ Id = 'FFOX-00-000025'; Pref = 'browser.contentblocking.category' }
        @{ Id = 'FFOX-00-000026'; Pref = 'extensions.htmlaboutaddons.recommendations.enabled' }
    )
    $script:Omitted = @('FFOX-00-000001', 'FFOX-00-000006', 'FFOX-00-000016')
    $script:AllIds = @($script:Simple.Id) + @($script:Composite.Id) + @($script:Manual.Id)
}

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:PackPath = Join-Path $script:RepoRoot 'Content/Firefox'
    Import-Module (Join-Path $script:RepoRoot 'woscap.psd1') -Force
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'helpers/New-WoscapTestRegEntry.ps1')
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Firefox pack shape' {
    It 'has exactly the 30 spec rules and none of the omitted ones' -ForEach @(@{ Ids = $script:AllIds; Omitted = $script:Omitted }) {
        $pack = InModuleScope woscap -Parameters @{ P = $script:PackPath } { Import-ContentPack -Path $P -WarningAction SilentlyContinue }
        @($pack.Keys | Sort-Object) | Should -Be @($Ids | Sort-Object)
        $pack.Count | Should -Be 30
        foreach ($id in $Omitted) { $pack.ContainsKey($id) | Should -BeFalse }
    }

    It 'loads without schema warnings' {
        InModuleScope woscap -Parameters @{ P = $script:PackPath } {
            $warnings = $null
            $null = Import-ContentPack -Path $P -WarningVariable warnings -WarningAction SilentlyContinue
            @($warnings) | Should -BeNullOrEmpty
        }
    }

    It 'reads only HKLM Firefox policy keys' {
        $pack = InModuleScope woscap -Parameters @{ P = $script:PackPath } { Import-ContentPack -Path $P -WarningAction SilentlyContinue }
        $paths = foreach ($d in $pack.Values) {
            if ($d.Type -eq 'Registry') { $d.Path }
            elseif ($d.Type -eq 'All') { @($d.Checks).Path }
            elseif ($d.Type -eq 'Manual') { @($d.Evidence.Checks).Path }
        }
        foreach ($p in $paths) { $p | Should -Match '^HKLM:\\SOFTWARE\\Policies\\Mozilla\\Firefox(\\|$)' }
        foreach ($d in $pack.Values) { $d.ContainsKey('AbsentIsPass') | Should -BeFalse }
    }

    It 'automates only the single-value REG_DWORD eq rules' {
        InModuleScope woscap -Parameters @{ P = $script:PackPath } {
            $pack = Import-ContentPack -Path $P -WarningAction SilentlyContinue
            $rules = @($pack.Keys | ForEach-Object { [pscustomobject]@{ StigId = $_; Title = $_; Status = 'Open' } })
            $plan = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            $auto = @($plan | Where-Object { $_.Automatable })
            foreach ($a in $auto) {
                $desc = $pack[$a.StigId]
                $desc.Type | Should -Be 'Registry'
                $desc.Operator | Should -Be 'eq'
                $a.Registry.Kind | Should -Be 'dword'
                $a.Registry.Path | Should -Be $desc.Path
                $a.Registry.Name | Should -Be $desc.Name
            }
            # Case-sensitive string enums, nested composites and Preferences stay manual.
            foreach ($id in 'FFOX-00-000002', 'FFOX-00-000021', 'FFOX-00-000009', 'FFOX-00-000017', 'FFOX-00-000029', 'FFOX-00-000037', 'FFOX-00-000003') {
                ($plan | Where-Object StigId -eq $id).Automatable | Should -BeFalse
            }
            $auto.Count | Should -Be 18
        }
    }
}

# Representative states per rule: good passes, bad fails, absent fails, unreadable is Error.
Describe 'Firefox single-value rules' {
    It '<Id> passes good, fails bad, absent and unreadable' -ForEach $script:Simple {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; Rule = $_ } {
            param($P, $Rule)
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)[$Rule.Id]
            $d.Type | Should -Be 'Registry'
            $d.Path | Should -Be $Rule.Path
            $d.Name | Should -Be $Rule.Name
            $script:val = $null
            $script:key = "$($Rule.Path)|$($Rule.Name)"
            Mock Get-RegValueEntry { New-WoscapTestRegEntry $(if ("$Path|$Name" -eq $script:key) { $script:val } else { $null }) }

            $got = [ordered]@{}
            foreach ($v in $Rule.Good) { $script:val = $v; $got["good '$v'"] = (Test-Descriptor -Descriptor $d).Result }
            foreach ($v in $Rule.Bad)  { $script:val = $v; $got["bad '$v'"]  = (Test-Descriptor -Descriptor $d).Result }
            $script:val = $null; $got['absent'] = (Test-Descriptor -Descriptor $d).Result
            $script:val = New-WoscapUnreadable -Reason 'test: access denied'; $got['unreadable'] = (Test-Descriptor -Descriptor $d).Result

            $bad = foreach ($k in $got.Keys) {
                $want = if ($k -like 'good*') { 'Pass' } elseif ($k -eq 'unreadable') { 'Error' } else { 'Fail' }
                if ($got[$k] -ne $want) { "${k}: expected $want, got $($got[$k])" }
            }
            @($bad) | Should -BeNullOrEmpty
        }
    }
}

# All named values must hold; any one wrong or missing fails; any unreadable is Error.
Describe 'Firefox nested-object rules' {
    It '<Id> requires every value under its policy subkey' -ForEach $script:Composite {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; Rule = $_ } {
            param($P, $Rule)
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)[$Rule.Id]
            $d.Type | Should -Be 'All'
            @($d.Checks | Where-Object { -not $_.ContainsKey('AbsentIsPass') } | ForEach-Object { "$($_.Path)|$($_.Name)=$($_.Expected)|$($_.Operator)" }) |
                Should -Be @($Rule.Expect.Keys | ForEach-Object { "$($Rule.Path)|$_=$($Rule.Expect[$_])|eq" })
            $script:reg = @{}
            Mock Get-RegValueEntry { New-WoscapTestRegEntry $($k = "$Path|$Name"; if ($script:reg.ContainsKey($k)) { $script:reg[$k] } else { $null }) }
            $setGood = { $script:reg = @{}; foreach ($n in $Rule.Expect.Keys) { $script:reg["$($Rule.Path)|$n"] = $Rule.Expect[$n] } }

            $miss = [System.Collections.Generic.List[string]]::new()
            & $setGood
            if ((Test-Descriptor -Descriptor $d).Result -ne 'Pass') { $miss.Add('all good did not Pass') }
            foreach ($n in $Rule.Expect.Keys) {
                $k = "$($Rule.Path)|$n"
                & $setGood; $script:reg[$k] = 1 - $Rule.Expect[$n]
                if ((Test-Descriptor -Descriptor $d).Result -ne 'Fail') { $miss.Add("$n wrong did not Fail") }
                & $setGood; $script:reg.Remove($k)
                if ((Test-Descriptor -Descriptor $d).Result -ne 'Fail') { $miss.Add("$n absent did not Fail") }
            }
            & $setGood; $script:reg["$($Rule.Path)|$(@($Rule.Expect.Keys)[0])"] = New-WoscapUnreadable -Reason 'test: access denied'
            if ((Test-Descriptor -Descriptor $d).Result -ne 'Error') { $miss.Add('unreadable did not Error') }
            @($miss) | Should -BeNullOrEmpty
        }
    }
}

Describe 'Firefox FirefoxHome Stories override' {
    It 'FFOX-00-000029 fails when Stories or SponsoredStories is on, passes when absent or 0' {
        InModuleScope woscap -Parameters @{ P = $script:PackPath } {
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)['FFOX-00-000029']
            $k = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome'
            $script:reg = @{}
            Mock Get-RegValueEntry { New-WoscapTestRegEntry $($x = "$Path|$Name"; if ($script:reg.ContainsKey($x)) { $script:reg[$x] } else { $null }) }
            $base = @{ Search = 0; TopSites = 0; SponsoredTopSites = 0; Pocket = 0; SponsoredPocket = 0; Highlights = 0; Snippets = 0; Locked = 1 }
            $cases = @(
                @(@{}, 'Pass'), @(@{ Stories = 0; SponsoredStories = 0 }, 'Pass'),
                @(@{ Stories = 1 }, 'Fail'), @(@{ SponsoredStories = 1 }, 'Fail')
            )
            $miss = foreach ($c in $cases) {
                $script:reg = @{}
                foreach ($n in $base.Keys) { $script:reg["$k|$n"] = $base[$n] }
                foreach ($n in $c[0].Keys) { $script:reg["$k|$n"] = $c[0][$n] }
                $got = (Test-Descriptor -Descriptor $d).Result
                if ($got -ne $c[1]) { "$(($c[0].Keys | ForEach-Object { "$_=$($c[0][$_])" }) -join ',') expected $($c[1]), got $got" }
            }
            @($miss) | Should -BeNullOrEmpty
        }
    }
}
Describe 'Firefox Preferences rules' {
    It '<Id> is Manual, names <Pref>, and reports every Preferences source as evidence' -ForEach $script:Manual {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; Id = $Id; Pref = $Pref } {
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)[$Id]
            $d.Type | Should -Be 'Manual'
            $d.Question | Should -Match ([regex]::Escape("`"$Pref`""))
            $d.Question | Should -Match 'Status "locked"'
            # The subkey form overrides the JSON value, so the question must say so.
            $d.Question | Should -Match 'ignores \(2\)'
            $f = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
            Mock Test-PathPresence { $true }
            Mock Get-RegValueEntry { New-WoscapTestRegEntry ($null) }
            Mock Get-RegValueEntry { New-WoscapTestRegEntry ('JSON') } -ParameterFilter { $Path -eq $f -and $Name -eq 'Preferences' }
            Mock Get-RegValueEntry { New-WoscapTestRegEntry ('PREF') } -ParameterFilter { $Path -eq "$f\Preferences" -and $Name -eq $Pref }
            Mock Get-RegValueEntry { New-WoscapTestRegEntry ('CAT') } -ParameterFilter { $Path -eq "$f\EnableTrackingProtection" -and $Name -eq 'Category' }
            $r = Test-Descriptor -Descriptor $d
            $r.Result | Should -Be 'NotReviewed'
            $want = if ($Id -eq 'FFOX-00-000025') { 'True; JSON; PREF; CAT' } else { 'True; JSON; PREF' }
            "$($r.Observed)" | Should -Be $want
            if ($Id -eq 'FFOX-00-000025') { $d.Question | Should -Match 'absent or "strict"' }
        }
    }
}

# Skipped where the licensed archive is absent (CI). Ties the spec above to DISA's text.
Describe 'Firefox spec reconciles with the V6R9 XCCDF' -Skip:$script:NoXccdf {
    BeforeAll {
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead((Join-Path $script:RepoRoot 'STIG/U_MOZ_Firefox_V6R9_STIG.zip'))
        try {
            $entry = @($zip.Entries | Where-Object { $_.FullName -like '*Manual-xccdf.xml' })[0]
            $reader = [System.IO.StreamReader]::new($entry.Open())
            try { $xml = [xml]$reader.ReadToEnd() } finally { $reader.Dispose() }
        } finally { $zip.Dispose() }
        $script:Rules = @{}
        foreach ($g in $xml.Benchmark.Group) { $script:Rules[[string]$g.Rule.version] = [string]$g.Rule.check.'check-content' }
    }

    It 'pack keys plus the omitted rules are exactly the 33 XCCDF rule versions' -ForEach @(@{ Omitted = $script:Omitted }) {
        $pack = InModuleScope woscap -Parameters @{ P = $script:PackPath } { Import-ContentPack -Path $P -WarningAction SilentlyContinue }
        $script:Rules.Count | Should -Be 33
        @($pack.Keys | Where-Object { -not $script:Rules.ContainsKey($_) }) | Should -BeNullOrEmpty
        @($script:Rules.Keys | Where-Object { -not $pack.ContainsKey($_) } | Sort-Object) | Should -Be @($Omitted | Sort-Object)
    }

    It '<Id> check-content states the policy and value the spec encodes' -ForEach @($script:Simple + $script:Composite) {
        $text = $script:Rules[$Id]
        $text | Should -Not -BeNullOrEmpty
        $text | Should -Match 'about:policies'
        foreach ($pattern in $Disa) { $text | Should -Match $pattern }
    }

    It '<Id> check-content requires Preferences <Pref> locked' -ForEach $script:Manual {
        $text = $script:Rules[$Id]
        $text | Should -Match '"Preferences"'
        $text | Should -Match ([regex]::Escape("`"$Pref`""))
        $text | Should -Match 'status of "locked"'
    }

    It 'omitted rules are the version, MIME-action and DoD-root rules' {
        $script:Rules['FFOX-00-000001'] | Should -Match 'supported version'
        $script:Rules['FFOX-00-000006'] | Should -Match 'about:preferences'
        $script:Rules['FFOX-00-000016'] | Should -Match 'AO-approved certificates'
    }
}

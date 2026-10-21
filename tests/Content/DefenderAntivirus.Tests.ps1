BeforeDiscovery {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:ZipPath = Join-Path $script:RepoRoot 'STIG/U_MS_Defender_Antivirus_V2R10_STIG.zip'
    $script:NoXccdf = -not (Test-Path -LiteralPath $script:ZipPath)

    # The rule spec the behavioural tests hold the pack to. The last Describe
    # re-derives it from the XCCDF check-content where the archive is present.
    $d = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $asr = "$d\Windows Defender Exploit Guard\ASR\Rules"
    $tsd = "$d\Threats\ThreatSeverityDefaultAction"
    $simple = @(
        # Id, Path, Name, Good values, Bad values, AbsentPass, Build-gated
        ,@('WNDF-AV-000003', $d, 'DisableRoutinelyTakingAction', @(0), @(1), $true, $false)
        ,@('WNDF-AV-000004', $d, 'DisableAntiSpyware', @(), @(0, 1), $true, $false)
        ,@('WNDF-AV-000005', "$d\Exclusions", 'Exclusions_Paths', @(0), @(1, 2), $true, $false)
        ,@('WNDF-AV-000006', "$d\Exclusions", 'Exclusions_Processes', @(0), @(1, 2), $true, $false)
        ,@('WNDF-AV-000007', "$d\Exclusions", 'DisableAutoExclusions', @(0), @(1), $false, $false)
        ,@('WNDF-AV-000008', "$d\Spynet", 'LocalSettingOverrideSpynetReporting', @(0), @(1), $true, $false)
        ,@('WNDF-AV-000009', "$d\Spynet", 'DisableBlockAtFirstSeen', @(0), @(1), $false, $false)
        ,@('WNDF-AV-000010', "$d\Spynet", 'SpynetReporting', @(1, 2), @(0, 3), $false, $false)
        ,@('WNDF-AV-000011', "$d\Spynet", 'SubmitSamplesConsent', @(1), @(0, 2, 3), $false, $false)
        ,@('WNDF-AV-000012', "$d\NIS", 'DisableProtocolRecognition', @(0), @(1), $true, $false)
        ,@('WNDF-AV-000013', "$d\Real-Time Protection", 'LocalSettingOverrideDisableOnAccessProtection', @(0), @(1), $true, $false)
        ,@('WNDF-AV-000014', "$d\Real-Time Protection", 'LocalSettingOverrideRealtimeScanDirection', @(0), @(1), $true, $false)
        ,@('WNDF-AV-000015', "$d\Real-Time Protection", 'LocalSettingOverrideDisableIOAVProtection', @(0), @(1), $true, $false)
        ,@('WNDF-AV-000016', "$d\Real-Time Protection", 'LocalSettingOverrideDisableBehaviorMonitoring', @(0), @(1), $true, $false)
        ,@('WNDF-AV-000017', "$d\Real-Time Protection", 'LocalSettingOverrideDisableRealtimeMonitoring', @(0), @(1), $true, $false)
        ,@('WNDF-AV-000023', "$d\Real-Time Protection", 'DisableScanOnRealtimeEnable', @(0), @(1), $true, $false)
        ,@('WNDF-AV-000028', "$d\Signature Updates", 'ASSignatureDue', @(1, 7), @(0, 8, 14), $false, $false)
        ,@('WNDF-AV-000029', "$d\Signature Updates", 'AVSignatureDue', @(1, 7), @(0, 8, 14), $false, $false)
        ,@('WNDF-AV-000030', "$d\Signature Updates", 'ScheduleDay', @(0), @(1, 8), $false, $false)
        ,@('WNDF-AV-000032', $asr, 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550', @('1'), @('0', '2', '01'), $false, $true)
        ,@('WNDF-AV-000033', $asr, 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A', @('1'), @('0', '2', '01'), $false, $true)
        ,@('WNDF-AV-000034', $asr, '3B576869-A4EC-4529-8536-B80A7769E899', @('1'), @('0', '2', '01'), $false, $true)
        ,@('WNDF-AV-000035', $asr, '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84', @('1'), @('0', '2', '01'), $false, $true)
        ,@('WNDF-AV-000036', $asr, 'D3E037E1-3EB8-44C8-A917-57927947596D', @('1'), @('0', '2', '01'), $false, $true)
        ,@('WNDF-AV-000037', $asr, '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC', @('1'), @('0', '2', '01'), $false, $true)
        ,@('WNDF-AV-000038', $asr, '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B', @('1'), @('0', '2', '01'), $false, $true)
        ,@('WNDF-AV-000040', $tsd, '4', @('2', '3'), @('1', '6'), $false, $false)
        ,@('WNDF-AV-000041', $tsd, '2', @('2', '3'), @('1', '6'), $false, $false)
        ,@('WNDF-AV-000042', $tsd, '1', @('2', '3'), @('1', '6'), $false, $false)
        ,@('WNDF-AV-000043', $asr, '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', @('1'), @('0', '2', '6'), $false, $false)
        ,@('WNDF-AV-000044', $asr, '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', @('1'), @('0', '2', '6'), $false, $false)
        ,@('WNDF-AV-000045', $asr, 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', @('1'), @('0', '2', '6'), $false, $false)
        ,@('WNDF-AV-000046', $asr, 'c1db55ab-c21a-4637-bb3f-a12568109d35', @('1'), @('0', '2', '6'), $false, $false)
        ,@('WNDF-AV-000047', $asr, 'd1e49aac-8f56-4280-b9ba-993a6d77406c', @('2'), @('0', '1', '6'), $false, $false)
        ,@('WNDF-AV-000048', $asr, 'e6db77e5-3df2-4cf1-b95a-636979351e5b', @('2'), @('0', '1', '6'), $false, $false)
        ,@('WNDF-AV-000049', $asr, '01443614-cd74-433a-b99e-2ecdc07bfc25', @('2'), @('0', '1', '6'), $false, $false)
        ,@('WNDF-AV-000050', $asr, '26190899-1602-49e8-8b27-eb1d0a1ce869', @('1'), @('0', '2', '6'), $false, $false)
        ,@('WNDF-AV-000051', $asr, '56a863a9-875e-4185-98a7-b882c64b5ce5', @('1'), @('0', '2', '6'), $false, $false)
        ,@('WNDF-AV-000052', $d, 'DisableLocalAdminMerge', @(1), @(0), $false, $false)
        ,@('WNDF-AV-000055', $d, 'RandomizeScheduleTaskTimes', @(1), @(0), $false, $false)
        ,@('WNDF-AV-000056', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options', 'UILockdown', @(1), @(0), $false, $false)
        ,@('WNDF-AV-000057', "$d\MpEngine", 'EnableFileHashComputation', @(1), @(0), $false, $false)
        ,@('WNDF-AV-000058', "$d\MpEngine", 'MpBafsExtendedTimeout', @(50), @(0, 49, 51), $false, $false)
        ,@('WNDF-AV-000064', "$d\Real-Time Protection", 'DisableScriptScanning', @(0), @(1), $false, $false)
        ,@('WNDF-AV-000065', "$d\Real-Time Protection", 'OobeEnableRtpAndSigUpdate', @(1), @(0), $false, $false)
        ,@('WNDF-AV-000070', "$d\Features", 'PassiveRemediation', @(1), @(0), $false, $false)
        ,@('WNDF-AV-000071', "$d\Reporting", 'EnableDynamicSignatureDroppedEventReporting', @(1), @(0), $false, $false)
        ,@('WNDF-AV-000072', "$d\Scan", 'QuickScanIncludeExclusions', @(1), @(0), $false, $false)
        ,@('WNDF-AV-000073', "$d\MpEngine", 'MpCloudBlockLevel', @(2), @(0, 1, 4), $false, $false)
        ,@('WNDF-AV-000074', "$d\NIS", 'EnableConvertWarnToBlock', @(1), @(0), $false, $false)
        ,@('WNDF-AV-000075', "$d\NIS", 'AllowSwitchToAsyncInspection', @(1), @(0), $false, $false)
        ,@('WNDF-AV-000076', "$d\Scan", 'DisablePackedExeScanning', @(0), @(1), $false, $false)
        ,@('WNDF-AV-000077', "$d\Scan", 'DisableHeuristics', @(0), @(1), $false, $false)
        ,@('WNDF-AV-000100', $d, 'HideExclusionsFromLocalAdmins', @(1), @(0), $false, $false)
    )
    $script:Simple = foreach ($r in $simple) {
        @{ Id = $r[0]; Path = $r[1]; Name = $r[2]; Good = $r[3]; Bad = $r[4]; AbsentPass = $r[5]; Gated = $r[6] }
    }

    # GPO value with an Intune "Policy Manager" alternate consulted only when the GPO value is absent.
    $pm = "$d\Policy Manager"
    $alt = @(
        # Id, GPO path, GPO name, GPO good, GPO bad, PM name, PM good, PM bad, both-absent passes, Build-gated
        ,@('WNDF-AV-000001', $d, 'PUAProtection', @(1), @(0, 2), 'PUAProtection', @(1), @(0, 2), $false, $false)
        ,@('WNDF-AV-000018', "$d\Real-Time Protection", 'RealtimeScanDirection', @(0), @(1, 2), 'RealtimeScanDirection', @(0), @(1, 2), $false, $false)
        ,@('WNDF-AV-000019', "$d\Real-Time Protection", 'DisableOnAccessProtection', @(0), @(1), 'AllowOnAccessProtection', @(1), @(0), $true, $false)
        ,@('WNDF-AV-000020', "$d\Real-Time Protection", 'DisableIOAVProtection', @(0), @(1), 'AllowIOAVProtection', @(1), @(0), $true, $false)
        ,@('WNDF-AV-000021', "$d\Real-Time Protection", 'DisableRealtimeMonitoring', @(0), @(1), 'AllowRealtimeMonitoring', @(1), @(0), $true, $false)
        ,@('WNDF-AV-000022', "$d\Real-Time Protection", 'DisableBehaviorMonitoring', @(0), @(1), 'AllowBehaviorMonitoring', @(1), @(0), $true, $false)
        ,@('WNDF-AV-000024', "$d\Scan", 'DisableArchiveScanning', @(0), @(1), 'AllowArchiveScanning', @(1), @(0), $true, $false)
        ,@('WNDF-AV-000025', "$d\Scan", 'DisableRemovableDriveScanning', @(0), @(1), 'AllowFullScanRemovableDriveScanning', @(1), @(0), $false, $false)
        ,@('WNDF-AV-000026', "$d\Scan", 'ScheduleDay', @(0, 7), @(8), 'ScheduleScanDay', @(0, 7), @(8), $false, $false)
        ,@('WNDF-AV-000027', "$d\Scan", 'DisableEmailScanning', @(0), @(1), 'AllowEmailScanning', @(1), @(0), $false, $false)
        ,@('WNDF-AV-000031', $tsd, '5', @('2', '3'), @('1', '6'), 'ThreatSeverityDefaultAction', @(1, 2), @(0), $false, $false)
        ,@('WNDF-AV-000039', "$d\Windows Defender Exploit Guard\Network Protection", 'EnableNetworkProtection', @(1), @(0, 2), 'EnableNetworkProtection', @(1), @(0, 2), $false, $true)
    )
    $script:Alt = foreach ($r in $alt) {
        @{ Id = $r[0]; GpoPath = $r[1]; GpoName = $r[2]; GpoGood = $r[3]; GpoBad = $r[4]
           PmPath = $pm; PmName = $r[5]; PmGood = $r[6]; PmBad = $r[7]; BothAbsentPass = $r[8]; Gated = $r[9] }
    }
    $script:AllIds = @($script:Simple | ForEach-Object { $_.Id }) + @($script:Alt | ForEach-Object { $_.Id }) + 'WNDF-AV-000068'
}

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:PackPath = Join-Path $script:RepoRoot 'Content/DefenderAntivirus'
    Import-Module (Join-Path $script:RepoRoot 'woscap.psd1') -Force
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'helpers/New-WoscapTestRegEntry.ps1')
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Defender Antivirus pack shape' {
    It 'has every spec rule plus the WNDF-AV-000068 Manual entry, 67 in all' -ForEach @(@{ Ids = $script:AllIds }) {
        $pack = InModuleScope woscap -Parameters @{ P = $script:PackPath } { Import-ContentPack -Path $P -WarningAction SilentlyContinue }
        @($pack.Keys | Sort-Object) | Should -Be @($Ids | Sort-Object)
        $pack.Count | Should -Be 67
        $pack['WNDF-AV-000068'].Type | Should -Be 'Manual'
        $pack['WNDF-AV-000068'].Question | Should -Match 'Windows Server'
    }

    It 'loads without schema warnings' {
        InModuleScope woscap -Parameters @{ P = $script:PackPath } {
            $warnings = $null
            $null = Import-ContentPack -Path $P -WarningVariable warnings -WarningAction SilentlyContinue
            @($warnings) | Should -BeNullOrEmpty
        }
    }

    It 'automates only single-value Registry fixes, writing ASR and threat values as REG_SZ' {
        InModuleScope woscap -Parameters @{ P = $script:PackPath } {
            $pack = Import-ContentPack -Path $P -WarningAction SilentlyContinue
            $rules = @($pack.Keys | ForEach-Object { [pscustomobject]@{ StigId = $_; Title = $_; Status = 'Open' } })
            $plan = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            foreach ($a in @($plan | Where-Object { $_.Automatable })) {
                $desc = $pack[$a.StigId]
                $desc.Type | Should -Be 'Registry'
                $desc.Operator | Should -Be 'eq'
                if ($desc.Path -match 'ASR\\Rules$') { $a.Writes[0].Kind | Should -Be 'string' } else { $a.Writes[0].Kind | Should -Be 'dword' }
            }
            # Composites, sets, exists and Manual stay manual.
            foreach ($id in 'WNDF-AV-000001', 'WNDF-AV-000004', 'WNDF-AV-000010', 'WNDF-AV-000028', 'WNDF-AV-000040', 'WNDF-AV-000068') {
                ($plan | Where-Object StigId -eq $id).Automatable | Should -BeFalse
            }
            # Unclassified-only rules: a classified host scanned without its exception profile must not be rewritten.
            foreach ($id in 'WNDF-AV-000008', 'WNDF-AV-000009', 'WNDF-AV-000011') {
                $a = $plan | Where-Object StigId -eq $id
                $a.Automatable | Should -BeFalse
                $a.ManualReason | Should -Match 'classified'
            }
            @($plan | Where-Object { $_.Automatable }).Count | Should -Be 44
        }
    }
}

# Representative states per rule, not a cross-product: every good value passes,
# every bad value fails, absence follows DISA's wording, unreadable is Error.
Describe 'Defender Antivirus single-value rules' {
    It '<Id> passes good, fails bad, handles absent and unreadable' -ForEach $script:Simple {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; Rule = $_ } {
            param($P, $Rule)
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)[$Rule.Id]
            $script:val = $null
            $script:key = "$($Rule.Path)|$($Rule.Name)"
            Mock Get-RegValueEntry { New-WoscapTestRegEntry $(if ("$Path|$Name" -eq $script:key) { $script:val } else { $null }) }
            Mock Get-WoscapMachineFact { 22631 } -ParameterFilter { $Fact -eq 'OsBuild' }

            $got = @{}
            foreach ($v in $Rule.Good) { $script:val = $v; $got["good $v"] = (Test-Descriptor -Descriptor $d).Result }
            foreach ($v in $Rule.Bad)  { $script:val = $v; $got["bad $v"]  = (Test-Descriptor -Descriptor $d).Result }
            $script:val = $null;  $got['absent'] = (Test-Descriptor -Descriptor $d).Result
            $script:val = New-WoscapUnreadable -Reason 'test: access denied'; $got['unreadable'] = (Test-Descriptor -Descriptor $d).Result

            $bad = foreach ($k in $got.Keys) {
                $want = if ($k -like 'good*') { 'Pass' } elseif ($k -like 'bad*') { 'Fail' }
                        elseif ($k -eq 'absent') { if ($Rule.AbsentPass) { 'Pass' } else { 'Fail' } }
                        else { 'Error' }
                if ($got[$k] -ne $want) { "${k}: expected $want, got $($got[$k])" }
            }
            @($bad) | Should -BeNullOrEmpty
        }
    }
}

# Asserted invariants for GPO-or-Intune rules:
#   - a present GPO value alone decides (a compliant Intune value never rescues it);
#   - the Intune value decides only when the GPO value is absent;
#   - a compliant GPO value passes even when the Intune key is unreadable;
#   - any unreadable read that can decide the verdict is Error.
Describe 'Defender Antivirus GPO-or-Intune rules' {
    It '<Id> matches the policy-then-alternate model' -ForEach $script:Alt {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; Rule = $_ } {
            param($P, $Rule)
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)[$Rule.Id]
            $gk = "$($Rule.GpoPath)|$($Rule.GpoName)"; $pk = "$($Rule.PmPath)|$($Rule.PmName)"
            $script:reg = @{}
            Mock Get-RegValueEntry { New-WoscapTestRegEntry $($k = "$Path|$Name"; if ($script:reg.ContainsKey($k)) { $script:reg[$k] } else { $null }) }
            Mock Get-WoscapMachineFact { 22631 } -ParameterFilter { $Fact -eq 'OsBuild' }
            $bad = New-WoscapUnreadable -Reason 'test: access denied'
            $absent = [object]::new()

            $cases = [System.Collections.Generic.List[object]]::new()
            # A compliant GPO value gates the fallback NA, so an unreadable Intune key cannot make it Error.
            @($d.Checks)[1].ContainsKey('Applicability') | Should -BeTrue
            foreach ($g in $Rule.GpoGood) { $cases.Add(@($g, $absent, 'Pass')); $cases.Add(@($g, $Rule.PmBad[0], 'Pass')); $cases.Add(@($g, $bad, 'Pass')) }
            foreach ($g in $Rule.GpoBad)  { $cases.Add(@($g, $absent, 'Fail')); $cases.Add(@($g, $Rule.PmGood[0], 'Fail')) }
            foreach ($m in $Rule.PmGood)  { $cases.Add(@($absent, $m, 'Pass')) }
            foreach ($m in $Rule.PmBad)   { $cases.Add(@($absent, $m, 'Fail')) }
            $cases.Add(@($absent, $absent, $(if ($Rule.BothAbsentPass) { 'Pass' } else { 'Fail' })))
            $cases.Add(@($absent, $bad, 'Error'))
            $cases.Add(@($bad, $Rule.PmGood[0], 'Error'))

            $mismatches = foreach ($c in $cases) {
                $script:reg = @{}
                if (-not [object]::ReferenceEquals($c[0], $absent)) { $script:reg[$gk] = $c[0] }
                if (-not [object]::ReferenceEquals($c[1], $absent)) { $script:reg[$pk] = $c[1] }
                $got = (Test-Descriptor -Descriptor $d).Result
                $label = { param($v) if ([object]::ReferenceEquals($v, $absent)) { 'absent' } elseif (Test-WoscapUnreadable -Value $v) { 'unreadable' } else { "$v" } }
                if ($got -ne $c[2]) { "gpo=$(& $label $c[0]) pm=$(& $label $c[1]): expected $($c[2]), got $got" }
            }
            @($mismatches) | Should -BeNullOrEmpty
        }
    }
}

Describe 'Defender Antivirus applicability' {
    It '<Id> is NA before Windows 10 v1709 only where DISA says so' -ForEach @($script:Simple + $script:Alt) {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; Id = $Id; Gated = $Gated } {
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)[$Id]
            Mock Get-RegValueEntry { New-WoscapTestRegEntry ($null) }
            Mock Get-WoscapMachineFact { 15063 } -ParameterFilter { $Fact -eq 'OsBuild' }
            $old = (Test-Descriptor -Descriptor $d).Result
            Mock Get-WoscapMachineFact { New-WoscapUnreadable -Reason 'test: CIM down' } -ParameterFilter { $Fact -eq 'OsBuild' }
            $unknown = (Test-Descriptor -Descriptor $d).Result
            if ($Gated) {
                $d.Applicability.Keys | Should -Be @('OsBuildAtLeast')
                $d.Applicability.OsBuildAtLeast | Should -Be 16299
                $old | Should -Be 'NA'
                $unknown | Should -Be 'Error'
            } else {
                $d.ContainsKey('Applicability') | Should -BeFalse
                $old | Should -Not -Be 'NA'
            }
        }
    }

    It 'WNDF-AV-000068 is NotReviewed and reports the server value as evidence' {
        InModuleScope woscap -Parameters @{ P = $script:PackPath } {
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)['WNDF-AV-000068']
            Mock Get-RegValueEntry { New-WoscapTestRegEntry (1) } -ParameterFilter { $Name -eq 'AllowNetworkProtectionOnWinServer' }
            $r = Test-Descriptor -Descriptor $d
            $r.Result | Should -Be 'NotReviewed'
            "$($r.Observed)" | Should -Be '1'
        }
    }
}

# Skipped where the licensed archive is absent (CI). Ties the spec above to DISA's text.
Describe 'Defender Antivirus spec reconciles with the V2R10 XCCDF' -Skip:$script:NoXccdf {
    BeforeAll {
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead((Join-Path $script:RepoRoot 'STIG/U_MS_Defender_Antivirus_V2R10_STIG.zip'))
        try {
            $entry = @($zip.Entries | Where-Object { $_.FullName -like '*Manual-xccdf.xml' })[0]
            $reader = [System.IO.StreamReader]::new($entry.Open())
            try { $xml = [xml]$reader.ReadToEnd() } finally { $reader.Dispose() }
        } finally { $zip.Dispose() }
        $script:Rules = @{}
        foreach ($g in $xml.Benchmark.Group) { $script:Rules[[string]$g.Rule.version] = [string]$g.Rule.check.'check-content' }
        # Check-content writes HKLM\Software\...; compare paths case-insensitively in that form.
        $script:ToDisa = { param($p) ($p -replace '^HKLM:', 'HKLM') }
    }

    It 'pack keys and XCCDF rule versions are the same 67 rules' {
        $pack = InModuleScope woscap -Parameters @{ P = $script:PackPath } { Import-ContentPack -Path $P -WarningAction SilentlyContinue }
        @($pack.Keys | Where-Object { -not $script:Rules.ContainsKey($_) }) | Should -BeNullOrEmpty
        @($script:Rules.Keys | Where-Object { -not $pack.ContainsKey($_) }) | Should -BeNullOrEmpty
        $script:Rules.Count | Should -Be 67
    }

    It '<Id> single-value spec matches the check-content' -ForEach $script:Simple {
        $text = $script:Rules[$Id]
        $text | Should -Not -BeNullOrEmpty
        $text.IndexOf((& $script:ToDisa $Path), [StringComparison]::OrdinalIgnoreCase) | Should -BeGreaterOrEqual 0
        $text | Should -Match ('"' + [regex]::Escape($Name) + '"')
        ($text -match 'If the value (does not exist|"[^"]+" does not exist), this is not a finding') | Should -Be $AbsentPass
        ($text -match 'v1709') | Should -Be $Gated
        $text | Should -Not -Match 'Policy Manager'
        if ($Path -match 'ASR\\Rules$|ThreatSeverityDefaultAction$') {
            $vals = @($Good | ForEach-Object { [regex]::Escape($_) }) -join '|'
            $text | Should -Match ('is "?REG_SZ = (' + $vals + ')')
        } elseif ($Good.Count -eq 1 -and -not $AbsentPass) {
            $text | Should -Match ('REG_DWORD = ' + $Good[0] + '\b')
        }
    }

    It '<Id> alternate spec matches the check-content' -ForEach $script:Alt {
        $text = $script:Rules[$Id]
        $text.IndexOf((& $script:ToDisa $GpoPath), [StringComparison]::OrdinalIgnoreCase) | Should -BeGreaterOrEqual 0
        $text | Should -Match ('"' + [regex]::Escape($GpoName) + '"')
        $alt = $text.Substring($text.IndexOf('Alternate Check'))
        $alt | Should -Match 'Policy Manager'
        $alt | Should -Match ('"' + [regex]::Escape($PmName) + '"')
        ($text -match 'If the value does not exist, this is not a finding') | Should -Be $BothAbsentPass
        ($text -match 'v1709') | Should -Be $Gated
    }

    It 'WNDF-AV-000068 is NA on desktops; classified and third-party NAs are as documented' {
        $script:Rules['WNDF-AV-000068'] | Should -Match 'not applicable to desktops'
        foreach ($id in 'WNDF-AV-000008', 'WNDF-AV-000009', 'WNDF-AV-000010', 'WNDF-AV-000011') { $script:Rules[$id] | Should -Match 'applicable to unclassified systems' }
        foreach ($id in 'WNDF-AV-000028', 'WNDF-AV-000029') { $script:Rules[$id] | Should -Match 'third-party' }
        # "Disabled" (value 0) is as compliant as "Not Configured" (absent).
        foreach ($id in 'WNDF-AV-000005', 'WNDF-AV-000006') { $script:Rules[$id] | Should -Match 'is set to "Disabled" or "Not Configured' }
    }
}

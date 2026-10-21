BeforeDiscovery {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:XccdfPath = Join-Path $script:RepoRoot 'STIG/U_MS_Windows_Defender_Firewall_V2R2_STIG/U_MS_Windows_Defender_Firewall_V2R2_Manual_STIG/U_MS_Windows_Defender_Firewall_STIG_V2R2_Manual-xccdf.xml'
    $script:NoXccdf = -not (Test-Path -LiteralPath $script:XccdfPath)

    # The rule spec the behavioural tests hold the pack to. The last Describe
    # re-derives it from the XCCDF check-content where that file is present.
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
    $loc = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
    $profiles = @{
        Domain  = @{ Policy = "$pol\DomainProfile";  Local = "$loc\DomainProfile" }
        Private = @{ Policy = "$pol\PrivateProfile"; Local = "$loc\StandardProfile" }
        Public  = @{ Policy = "$pol\PublicProfile";  Local = "$loc\PublicProfile" }
    }
    $rows = @(
        # Id, Profile, Logging subkey, Name, Operator, Value, PolicyOnly
        ,@('WNFWA-000001', 'Domain',  $false, 'EnableFirewall',             'eq',  1,     $false)
        ,@('WNFWA-000002', 'Private', $false, 'EnableFirewall',             'eq',  1,     $false)
        ,@('WNFWA-000003', 'Public',  $false, 'EnableFirewall',             'eq',  1,     $false)
        ,@('WNFWA-000004', 'Domain',  $false, 'DefaultInboundAction',       'eq',  1,     $false)
        ,@('WNFWA-000005', 'Domain',  $false, 'DefaultOutboundAction',      'eq',  0,     $false)
        ,@('WNFWA-000009', 'Domain',  $true,  'LogFileSize',                'ge',  16384, $false)
        ,@('WNFWA-000010', 'Domain',  $true,  'LogDroppedPackets',          'eq',  1,     $false)
        ,@('WNFWA-000011', 'Domain',  $true,  'LogSuccessfulConnections',   'eq',  1,     $false)
        ,@('WNFWA-000012', 'Private', $false, 'DefaultInboundAction',       'eq',  1,     $false)
        ,@('WNFWA-000013', 'Private', $false, 'DefaultOutboundAction',      'eq',  0,     $false)
        ,@('WNFWA-000017', 'Private', $true,  'LogFileSize',                'ge',  16384, $false)
        ,@('WNFWA-000018', 'Private', $true,  'LogDroppedPackets',          'eq',  1,     $false)
        ,@('WNFWA-000019', 'Private', $true,  'LogSuccessfulConnections',   'eq',  1,     $false)
        ,@('WNFWA-000020', 'Public',  $false, 'DefaultInboundAction',       'eq',  1,     $false)
        ,@('WNFWA-000021', 'Public',  $false, 'DefaultOutboundAction',      'eq',  0,     $false)
        ,@('WNFWA-000024', 'Public',  $false, 'AllowLocalPolicyMerge',      'eq',  0,     $true)
        ,@('WNFWA-000025', 'Public',  $false, 'AllowLocalIPsecPolicyMerge', 'eq',  0,     $true)
        ,@('WNFWA-000027', 'Public',  $true,  'LogFileSize',                'ge',  16384, $false)
        ,@('WNFWA-000028', 'Public',  $true,  'LogDroppedPackets',          'eq',  1,     $false)
        ,@('WNFWA-000029', 'Public',  $true,  'LogSuccessfulConnections',   'eq',  1,     $false)
    )
    $script:Spec = foreach ($r in $rows) {
        $p = $profiles[$r[1]]
        $sub = if ($r[2]) { '\Logging' } else { '' }
        @{
            Id           = $r[0]
            Profile      = $r[1]
            PolicyPath   = $p.Policy + $sub
            LocalPath    = if ($r[6]) { $null } else { $p.Local + $sub }
            Name         = $r[3]
            Operator     = $r[4]
            Value        = $r[5]
            # "Not a member of a domain -> NA": every Domain rule plus 000024/25.
            DomainOnly   = ($r[1] -eq 'Domain') -or $r[6]
            # "If the profile is not enabled (see V-1741x), this is also a finding".
            NeedsEnabled = ($r[3] -ne 'EnableFirewall')
            EnablePolicy = $p.Policy
            EnableLocal  = $p.Local
        }
    }
}

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:PackPath = Join-Path $script:RepoRoot 'Content/DefenderFirewall'
    Import-Module (Join-Path $script:RepoRoot 'woscap.psd1') -Force
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'helpers/New-WoscapTestRegEntry.ps1')
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Defender Firewall pack shape' {
    It 'has exactly the 20 automated rules plus the WNFWA-000100 Manual entry' -ForEach @(@{ Spec = $script:Spec }) {
        $pack = InModuleScope woscap -Parameters @{ P = $script:PackPath } { Import-ContentPack -Path $P -WarningAction SilentlyContinue }
        $expected = @($Spec | ForEach-Object { $_.Id }) + 'WNFWA-000100'
        @($pack.Keys | Sort-Object) | Should -Be @($expected | Sort-Object)
        $pack['WNFWA-000100'].Type | Should -Be 'Manual'
        $pack['WNFWA-000100'].Applicability.DomainJoined | Should -BeTrue
        $pack['WNFWA-000100'].Question | Should -Match 'management'
    }

    It 'loads without schema warnings' {
        InModuleScope woscap -Parameters @{ P = $script:PackPath } {
            $warnings = $null
            $null = Import-ContentPack -Path $P -WarningVariable warnings -WarningAction SilentlyContinue
            @($warnings) | Should -BeNullOrEmpty
        }
    }

    It '<Id> declares DomainJoined applicability only where DISA allows NA' -ForEach $script:Spec {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; Id = $Id; DomainOnly = $DomainOnly } {
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)[$Id]
            if ($DomainOnly) {
                $d.Applicability.Keys | Should -Be @('DomainJoined')
                $d.Applicability.DomainJoined | Should -BeTrue
            } else {
                $d.ContainsKey('Applicability') | Should -BeFalse
            }
        }
    }

    It 'has no rule the remediation planner would automate (all are composites)' {
        InModuleScope woscap -Parameters @{ P = $script:PackPath } {
            $pack = Import-ContentPack -Path $P -WarningAction SilentlyContinue
            $rules = @($pack.Keys | ForEach-Object { [pscustomobject]@{ StigId = $_; Title = $_; Status = 'Open' } })
            $plan = @(Get-WoscapRemediationPlan -FailedRule $rules -ContentPack $pack)
            @($plan | Where-Object { $_.Automatable }) | Should -BeNullOrEmpty
        }
    }
}

# Combinatorial: every rule over generated registry states, against a reference
# model of the check-content. Asserted invariants:
#   - a present policy value alone decides (a compliant local value never rescues it);
#   - the local value decides only when the policy value is absent;
#   - absent everywhere is a finding;
#   - a dependent rule fails when its profile is not effectively enabled;
#   - any unreadable value read is Error, never Pass.
Describe 'Defender Firewall verdicts over generated registry states' {
    It '<Id> matches the check-content model' -ForEach $script:Spec {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; Rule = $_ } {
            param($P, $Rule)
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)[$Rule.Id]
            $bad = New-WoscapUnreadable -Reason 'test: access denied'
            $script:reg = @{}
            Mock Get-RegValueEntry { New-WoscapTestRegEntry $($k = "$Path|$Name"; if ($script:reg.ContainsKey($k)) { $script:reg[$k] } else { $null }) }
            Mock Get-WoscapMachineFact { $true } -ParameterFilter { $Fact -eq 'DomainJoined' }

            $good = $Rule.Value
            $wrong = if ($Rule.Operator -eq 'ge') { $Rule.Value - 1 } elseif ($Rule.Value -eq 1) { 0 } else { 1 }
            $states = @(
                @{ Label = 'absent'; Value = $null; Ok = $false; Err = $false }
                @{ Label = 'good';   Value = $good;  Ok = $true;  Err = $false }
                @{ Label = 'wrong';  Value = $wrong; Ok = $false; Err = $false }
                @{ Label = 'unreadable'; Value = $bad; Ok = $false; Err = $true }
            )
            if ($Rule.Operator -eq 'ge') { $states += @{ Label = 'larger'; Value = 32767; Ok = $true; Err = $false } }
            # Enable states as (policy, local); profile is on when the effective value is 1.
            $enables = if ($Rule.NeedsEnabled) {
                @( @{ P = $null; L = 1;     On = $true }, @{ P = $null; L = 0; On = $false },
                   @{ P = 1;     L = 0;     On = $true }, @{ P = 0;     L = 1; On = $false },
                   @{ P = $null; L = $null; On = $false } )
            } else { @( @{ P = $null; L = $null; On = $true } ) }
            $localStates = if ($null -eq $Rule.LocalPath) { @($states[1]) } else { $states }

            $mismatches = foreach ($en in $enables) {
                foreach ($ps in $states) {
                    foreach ($ls in $localStates) {
                        $script:reg = @{}
                        if ($Rule.NeedsEnabled) {
                            if ($null -ne $en.P) { $script:reg["$($Rule.EnablePolicy)|EnableFirewall"] = $en.P }
                            if ($null -ne $en.L) { $script:reg["$($Rule.EnableLocal)|EnableFirewall"] = $en.L }
                        }
                        if ($null -ne $ps.Value) { $script:reg["$($Rule.PolicyPath)|$($Rule.Name)"] = $ps.Value }
                        # Policy-only rules get a compliant value at the local path, which must never be consulted.
                        $localPath = if ($null -eq $Rule.LocalPath) { $Rule.EnableLocal } else { $Rule.LocalPath }
                        if ($null -ne $ls.Value) { $script:reg["$localPath|$($Rule.Name)"] = $ls.Value }

                        $expect = if ($ps.Err -or ($ls.Err -and $null -ne $Rule.LocalPath)) { 'Error' }
                            else {
                                $valueOk = if ($null -ne $ps.Value) { $ps.Ok }
                                           elseif ($null -eq $Rule.LocalPath) { $false }
                                           else { $ls.Ok }
                                if ($valueOk -and $en.On) { 'Pass' } else { 'Fail' }
                            }
                        $got = (Test-Descriptor -Descriptor $d).Result
                        if ($got -ne $expect) { "enable(P=$($en.P),L=$($en.L)) policy=$($ps.Label) local=$($ls.Label): expected $expect, got $got" }
                    }
                }
            }
            @($mismatches) | Should -BeNullOrEmpty
        }
    }

    It '<Id> is NA off-domain only when DISA allows it, and Error when the fact is unreadable' -ForEach $script:Spec {
        InModuleScope woscap -Parameters @{ P = $script:PackPath; Rule = $_ } {
            param($P, $Rule)
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)[$Rule.Id]
            Mock Get-RegValueEntry { New-WoscapTestRegEntry ($null) }
            Mock Get-WoscapMachineFact { $false } -ParameterFilter { $Fact -eq 'DomainJoined' }
            $offDomain = (Test-Descriptor -Descriptor $d).Result
            if ($Rule.DomainOnly) { $offDomain | Should -Be 'NA' } else { $offDomain | Should -Be 'Fail' }

            Mock Get-WoscapMachineFact { New-WoscapUnreadable -Reason 'test: CIM down' } -ParameterFilter { $Fact -eq 'DomainJoined' }
            $unknown = (Test-Descriptor -Descriptor $d).Result
            if ($Rule.DomainOnly) { $unknown | Should -Be 'Error' } else { $unknown | Should -Be 'Fail' }
        }
    }

    It 'WNFWA-000100 is NA off-domain and NotReviewed on a domain member' {
        InModuleScope woscap -Parameters @{ P = $script:PackPath } {
            $d = (Import-ContentPack -Path $P -WarningAction SilentlyContinue)['WNFWA-000100']
            Mock Get-WoscapMachineFact { $false } -ParameterFilter { $Fact -eq 'DomainJoined' }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'NA'
            Mock Get-WoscapMachineFact { $true } -ParameterFilter { $Fact -eq 'DomainJoined' }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'NotReviewed'
        }
    }
}

# Skipped where the licensed XCCDF is absent (CI). Ties the spec above to DISA's text.
Describe 'Defender Firewall spec reconciles with the V2R2 XCCDF' -Skip:$script:NoXccdf {
    BeforeAll {
        $script:XccdfPath = Join-Path $script:RepoRoot 'STIG/U_MS_Windows_Defender_Firewall_V2R2_STIG/U_MS_Windows_Defender_Firewall_V2R2_Manual_STIG/U_MS_Windows_Defender_Firewall_STIG_V2R2_Manual-xccdf.xml'
        $xml = [xml](Get-Content -LiteralPath $script:XccdfPath -Raw)
        $script:Rules = @{}
        foreach ($g in $xml.Benchmark.Group) { $script:Rules[[string]$g.Rule.version] = [string]$g.Rule.check.'check-content' }
    }

    It 'every pack key is a rule in the XCCDF and the XCCDF has no rule the pack omits' {
        $pack = InModuleScope woscap -Parameters @{ P = $script:PackPath } { Import-ContentPack -Path $P -WarningAction SilentlyContinue }
        @($pack.Keys | Where-Object { -not $script:Rules.ContainsKey($_) }) | Should -BeNullOrEmpty
        @($script:Rules.Keys | Where-Object { -not $pack.ContainsKey($_) }) | Should -BeNullOrEmpty
        $script:Rules.Count | Should -Be 21
    }

    It '<Id> spec matches the check-content' -ForEach $script:Spec {
        $text = $script:Rules[$Id]
        $text | Should -Not -BeNullOrEmpty
        $blockPattern = 'Registry Hive:\s*HKEY_LOCAL_MACHINE\s*Registry Path:\s*(\\[^\r\n]+?)\\?\s*[\r\n]+\s*Value Name:\s*(\S+)\s*Type:\s*REG_DWORD\s*Value:\s*0x[0-9A-Fa-f]+\s*\((\d+)\)(\s*\(or greater\))?'
        $blocks = @([regex]::Matches($text, $blockPattern))
        $toPs = { param($m) 'HKLM:' + $m.Groups[1].Value.TrimEnd('\') }

        $first = $blocks[0]
        (& $toPs $first) | Should -Be $PolicyPath
        $first.Groups[2].Value | Should -Be $Name
        [int]$first.Groups[3].Value | Should -Be $Value
        $first.Groups[4].Success | Should -Be ($Operator -eq 'ge')

        if ($null -eq $LocalPath) {
            $blocks.Count | Should -Be 1
            $text | Should -Match 'If this registry value does not exist or is not configured as specified, this is a finding'
        } else {
            $blocks.Count | Should -Be 2
            $text | Should -Match 'If the following policy-based registry value exists and is not configured as specified, this is a finding'
            $text | Should -Match 'If the policy-based registry value does not exist, verify the following registry value'
            $second = $blocks[1]
            (& $toPs $second) | Should -Be $LocalPath
            $second.Groups[2].Value | Should -Be $Name
            [int]$second.Groups[3].Value | Should -Be $Value
            $second.Groups[4].Success | Should -Be ($Operator -eq 'ge')
        }

        ($text -match 'not a member of a domain') | Should -Be $DomainOnly
        ($text -match 'is not enabled \(see V-\d+\), this requirement is also a finding') | Should -Be $NeedsEnabled
    }

    It 'WNFWA-000100 is a manual review that is NA for servers and non-domain workstations' {
        $script:Rules['WNFWA-000100'] | Should -Match 'NA for servers and non domain workstations'
        $script:Rules['WNFWA-000100'] | Should -Not -Match 'Registry Path'
    }
}

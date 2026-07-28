BeforeAll {
    $script:RepoRoot   = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:PackPath   = Join-Path $script:RepoRoot 'Content/Windows11'
    $script:Manifest   = Import-PowerShellDataFile (Join-Path $script:PackPath 'coverage.psd1')
    Import-Module (Join-Path $script:RepoRoot 'woscap.psd1') -Force
    $script:Pack = InModuleScope woscap -Parameters @{ P = $script:PackPath } {
        Import-ContentPack -Path $P -WarningAction SilentlyContinue
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

# The guarantee this file exists to enforce:
#
#   Every rule in the benchmark has a DELIBERATE entry - automated or explicitly
#   Manual. "Unauthored" must be impossible to confuse with "deliberately left
#   to a human".
#
# The real XCCDF is licensed DISA content and is gitignored, so CI cannot parse
# it. The manifest carries the rule IDs (identifiers only, as already appear
# throughout checks.psd1) and CI checks the pack against that. The last Describe
# reconciles the manifest against the real XCCDF and is skipped where it is
# absent, so a drifting manifest is still caught locally and on any machine that
# has the content.

Describe 'Windows 11 pack coverage' {
    It 'has an entry for every rule in the coverage manifest' {
        $missing = @($script:Manifest.Keys | Where-Object { -not $script:Pack.ContainsKey($_) })
        $missing | Should -BeNullOrEmpty -Because 'a manifest rule with no pack entry reports Not_Reviewed with no explanation'
    }
    It 'has no pack entry that the manifest does not list' {
        $extra = @($script:Pack.Keys | Where-Object { -not $script:Manifest.ContainsKey($_) })
        $extra | Should -BeNullOrEmpty -Because 'an entry for a rule outside the benchmark is dead content'
    }
    It 'covers all 256 rules of V2R8' {
        $script:Manifest.Keys.Count | Should -Be 256
        $script:Pack.Keys.Count     | Should -Be 256
    }
    It 'agrees with the manifest on which rules are Manual' {
        $disagreements = foreach ($id in ($script:Manifest.Keys | Sort-Object)) {
            $declared = [string]$script:Manifest[$id]
            $actual   = if ([string]$script:Pack[$id].Type -eq 'Manual') { 'Manual' } else { 'Automated' }
            if ($declared -ne $actual) { "${id}: manifest says $declared, pack is $actual" }
        }
        @($disagreements) | Should -BeNullOrEmpty
    }
    It 'automates at least 240 of the 256 rules' {
        # A floor, not a target. It fails loudly if a future change quietly
        # downgrades a swathe of rules to Manual to make something else pass.
        $automated = @($script:Pack.Keys | Where-Object { [string]$script:Pack[$_].Type -ne 'Manual' })
        $automated.Count | Should -BeGreaterOrEqual 240
    }
    It 'gives every Manual entry a question for the reviewer to answer' {
        $unquestioned = foreach ($id in $script:Pack.Keys) {
            $d = $script:Pack[$id]
            if ([string]$d.Type -eq 'Manual' -and [string]::IsNullOrWhiteSpace([string]$d.Question)) { $id }
        }
        @($unquestioned) | Should -BeNullOrEmpty -Because 'a Manual entry with no question is indistinguishable from an unauthored one'
    }
}

Describe 'Windows 11 pack schema' {
    It 'every descriptor is structurally valid' {
        $problems = InModuleScope woscap -Parameters @{ Pack = $script:Pack } {
            foreach ($id in ($Pack.Keys | Sort-Object)) {
                $d = $Pack[$id]
                if ($d -isnot [hashtable]) { "${id}: not a hashtable"; continue }
                Test-WoscapDescriptorSchema -Descriptor $d -Context $id
            }
        }
        @($problems) | Should -BeNullOrEmpty
    }
    It 'no descriptor names an operator the comparator does not implement' {
        # Guards against the schema list and Compare-WoscapValue drifting apart.
        $valid = InModuleScope woscap {
            (Get-Command Compare-WoscapValue).Parameters['Operator'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
                ForEach-Object { $_.ValidValues }
        }
        $used = New-Object System.Collections.Generic.List[string]
        function Get-OperatorRecursive {
            param($Descriptor, $Sink)
            if ($Descriptor -isnot [hashtable]) { return }
            if ($Descriptor.ContainsKey('Operator')) { $Sink.Add([string]$Descriptor.Operator) }
            foreach ($key in @('Checks')) {
                if ($Descriptor.ContainsKey($key)) {
                    foreach ($child in @($Descriptor[$key])) { Get-OperatorRecursive -Descriptor $child -Sink $Sink }
                }
            }
            if ($Descriptor.ContainsKey('Evidence')) { Get-OperatorRecursive -Descriptor $Descriptor.Evidence -Sink $Sink }
        }
        foreach ($id in $script:Pack.Keys) { Get-OperatorRecursive -Descriptor $script:Pack[$id] -Sink $used }
        $unknown = @($used | Sort-Object -Unique | Where-Object { $valid -notcontains $_ })
        $unknown | Should -BeNullOrEmpty
    }
}

Describe 'Windows 11 manifest reconciles with the published benchmark' {
    BeforeAll {
        $script:XccdfPath = Join-Path $script:RepoRoot 'STIG/_extracted/U_MS_Windows_11_STIG_V2R8_Manual-xccdf.xml'
        $script:HaveXccdf = Test-Path -LiteralPath $script:XccdfPath
    }
    It 'lists exactly the rules the XCCDF defines' -Skip:(-not (Test-Path -LiteralPath (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'STIG/_extracted/U_MS_Windows_11_STIG_V2R8_Manual-xccdf.xml'))) {
        # Skipped where the licensed XCCDF is absent (CI). Locally this is what
        # catches a manifest that has drifted from the benchmark, including a
        # future revision that adds or renames rules.
        $xml = [xml](Get-Content -LiteralPath $script:XccdfPath -Raw)
        $ruleIds = @($xml.Benchmark.Group | ForEach-Object { $_.Rule.version })

        @($ruleIds | Where-Object { -not $script:Manifest.ContainsKey($_) }) |
            Should -BeNullOrEmpty -Because 'the benchmark defines a rule the manifest omits'
        @($script:Manifest.Keys | Where-Object { $ruleIds -notcontains $_ }) |
            Should -BeNullOrEmpty -Because 'the manifest lists a rule the benchmark does not define'
    }
}

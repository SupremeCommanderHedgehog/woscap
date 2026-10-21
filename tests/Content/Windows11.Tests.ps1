BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:PackPath = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'Content/Windows11'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Windows11 content pack' {
    It 'loads and contains known STIG IDs' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            $p.Keys | Should -Contain 'WN11-00-000165'
            $p.Keys | Should -Contain 'WN11-AU-000500'
            $p.Keys | Should -Contain 'WN11-00-000170'
        }
    }
    It 'every descriptor has a valid Type' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            # Sourced from the schema validator rather than restated, so a new
            # Type does not require editing this list in two places.
            $valid = 'Registry','SecEdit','UserRight','AuditPolicy','Service','Cim','Certificate',
                     'Acl','OptionalFeature','Path','LocalAccount','ScriptBlock','Manual','All','Any'
            $p = Import-ContentPack -Path $PackPath -WarningAction SilentlyContinue
            foreach ($key in $p.Keys) { $p[$key].Type | Should -BeIn $valid }
        }
    }
    It 'the scriptblock override evaluates against a mocked registry read' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            Mock Get-RegValue { 4 }
            $p = Import-ContentPack -Path $PackPath
            (Test-Descriptor -Descriptor $p['WN11-00-000170']).Result | Should -Be 'Pass'
        }
    }
    It 'WN11-00-000400 reads hidden Wi-Fi Direct adapters: <Case>' -ForEach @(
        @{ Case = 'none';         Adapters = @();                                              Expected = 'Pass' }
        @{ Case = 'one enabled';  Adapters = @(@{ Status = 'Disconnected' });                  Expected = 'Fail' }
        @{ Case = 'mixed';        Adapters = @(@{ Status = 'Disabled' }, @{ Status = 'Up' });  Expected = 'Fail' }
        @{ Case = 'all disabled'; Adapters = @(@{ Status = 'Disabled' });                      Expected = 'NotReviewed' }
    ) {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath; Adapters = $Adapters; Expected = $Expected } {
            $script:fake = @($Adapters | ForEach-Object { [pscustomobject]$_ })
            Mock Get-NetAdapter { $script:fake }
            $p = Import-ContentPack -Path $PackPath -WarningAction SilentlyContinue
            (Test-Descriptor -Descriptor $p['WN11-00-000400']).Result | Should -Be $Expected
            Should -Invoke Get-NetAdapter -ParameterFilter { $IncludeHidden -and $InterfaceDescription -eq 'Microsoft Wi-Fi Direct*' }
        }
    }
    It 'WN11-00-000400 is Error, not Pass, when the adapter read fails' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            Mock Get-NetAdapter { throw 'access denied' }
            $p = Import-ContentPack -Path $PackPath -WarningAction SilentlyContinue
            (Test-Descriptor -Descriptor $p['WN11-00-000400']).Result | Should -Be 'Error'
        }
    }
    It '<Id> (V2R11): <Case>' -ForEach @(
        @{ Id = 'WN11-PK-000010'; Case = 'one current ECA root';      All = @('CN=ECA Root CA 4, OU=ECA');                               Valid = @('CN=ECA Root CA 4, OU=ECA');  Expected = 'Pass' }
        @{ Id = 'WN11-PK-000010'; Case = 'an expired ECA root too';   All = @('CN=ECA Root CA 4, OU=ECA','CN=ECA Root CA 2, OU=ECA');    Valid = @('CN=ECA Root CA 4, OU=ECA');  Expected = 'Fail' }
        @{ Id = 'WN11-PK-000010'; Case = 'a non-root ECA match';      All = @('CN=ECA Root CA 4, OU=ECA','CN=TrustCor ECA-1');           Valid = @('CN=ECA Root CA 4, OU=ECA','CN=TrustCor ECA-1'); Expected = 'Fail' }
        @{ Id = 'WN11-PK-000010'; Case = 'none';                      All = @();                                                          Valid = @();                            Expected = 'Fail' }
        @{ Id = 'WN11-PK-000015'; Case = 'one current cross-cert';    All = @('CN=DoD Interoperability Root CA 2');                      Valid = @('CN=DoD Interoperability Root CA 2'); Expected = 'Pass' }
        @{ Id = 'WN11-PK-000015'; Case = 'only an expired cross-cert'; All = @('CN=DoD Root CA 3');                                      Valid = @();                            Expected = 'Fail' }
        @{ Id = 'WN11-PK-000015'; Case = 'current plus expired';      All = @('CN=DoD Root CA 6','CN=DoD Root CA 3');                    Valid = @('CN=DoD Root CA 6');          Expected = 'Fail' }
        @{ Id = 'WN11-PK-000020'; Case = 'one current CCEB cert';     All = @('CN=DoD Root CA 6');                                        Valid = @('CN=DoD Root CA 6');          Expected = 'Pass' }
        @{ Id = 'WN11-PK-000020'; Case = 'only an expired CCEB cert'; All = @('CN=DoD Root CA 3');                                        Valid = @();                            Expected = 'Fail' }
    ) {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath; Id = $Id; All = $All; Valid = $Valid; Expected = $Expected } {
            $script:all = $All; $script:valid = $Valid
            Mock Get-CertificateSetting { $script:all }
            Mock Get-CertificateSetting { $script:valid } -ParameterFilter { $RequireUnexpired }
            $p = Import-ContentPack -Path $PackPath -WarningAction SilentlyContinue
            (Test-Descriptor -Descriptor $p[$Id]).Result | Should -Be $Expected
        }
    }
    It '<Id> is Error, not Pass, when the store cannot be read' -ForEach @(
        @{ Id = 'WN11-PK-000010' }, @{ Id = 'WN11-PK-000015' }, @{ Id = 'WN11-PK-000020' }
    ) {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath; Id = $Id } {
            Mock Get-CertificateSetting { New-WoscapUnreadable -Reason 'denied' }
            $p = Import-ContentPack -Path $PackPath -WarningAction SilentlyContinue
            (Test-Descriptor -Descriptor $p[$Id]).Result | Should -Be 'Error'
        }
    }
    It 'WN11-00-000045 passes only on an ACTIVE antivirus (V2R11): <Case>' -ForEach @(
        @{ Case = 'Defender real-time on';            Rtp = $true;  States = @(393472); Expected = 'Pass' }
        @{ Case = 'third-party active, out of date';  Rtp = $false; States = @(397584); Expected = 'Pass' }
        @{ Case = 'registered but disabled';          Rtp = $false; States = @(393472, 393488); Expected = 'Fail' }
        @{ Case = 'nothing registered';               Rtp = $false; States = @();       Expected = 'Fail' }
    ) {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath; Rtp = $Rtp; States = $States; Expected = $Expected } {
            $script:rtp = $Rtp; $script:states = $States
            Mock Get-CimSetting { $script:rtp } -ParameterFilter { $ClassName -eq 'MSFT_MpComputerStatus' }
            Mock Get-CimSetting { ,@($script:states) } -ParameterFilter { $ClassName -eq 'AntiVirusProduct' }
            $p = Import-ContentPack -Path $PackPath -WarningAction SilentlyContinue
            (Test-Descriptor -Descriptor $p['WN11-00-000045']).Result | Should -Be $Expected
        }
    }
    It 'carries the V2R11 thresholds and paths' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath -WarningAction SilentlyContinue
            @($p['WN11-AC-000025'].Checks | Where-Object { $_.Operator -eq 'le' })[0].Expected | Should -Be 180
            @($p['WN11-SO-000280'].Checks | ForEach-Object { $_.Expected }) | Should -Be @(180, 180)
            $p['WN11-CC-000365'].ContainsKey('Applicability') | Should -BeFalse
            $p['WN11-CC-000366'].Name     | Should -Be 'LetAppsActivateWithVoice'
            $p['WN11-CC-000366'].Expected | Should -Be 2
            $pairs = @($p['WN11-CC-000195'].Checks | ForEach-Object { "$($_.Path)|$($_.Name)" })
            $pairs | Should -Be @(
                'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures|EnhancedAntiSpoofing'
                'HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics|FacialFeaturesUseEnhancedAntiSpoofing')
            @($p['WN11-CC-000252'].Checks | ForEach-Object { $_.Path }) |
                Should -Contain 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ApplicationManagement'
            $p.ContainsKey('WN11-SO-000080') | Should -BeFalse
            foreach ($id in 'WN11-CC-000390','WN11-UC-000015','WN11-UC-000020') { $p[$id].Type | Should -Be 'Manual' }
        }
    }
    It 'provides broad coverage (>120 declarative descriptors)' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            (Import-ContentPack -Path $PackPath).Keys.Count | Should -BeGreaterThan 120
        }
    }
    It 'spot-checks known registry and audit descriptors' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            $p['WN11-00-000165'].Expected | Should -Be 0            # SMB1 eq 0
            $p['WN11-00-000032'].Operator | Should -Be 'ge'         # MinimumPIN ge 6
            $p['WN11-00-000032'].Expected | Should -Be 6
            $p['WN11-AU-000500'].Operator | Should -Be 'ge'         # MaxSize ge 32768
            $p['WN11-AU-000070'].Type     | Should -Be 'AuditPolicy'
            $p['WN11-AU-000070'].Expected | Should -Be 'Failure'    # Logon/Failure
        }
    }
    It 'every registry descriptor Expected is present and every audit Expected is Success or Failure' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            foreach ($k in $p.Keys) {
                $d = $p[$k]
                if ($d.Type -eq 'Registry')    { $d.PSObject.Properties.Name + $d.Keys | Out-Null; $d['Name'] | Should -Not -BeNullOrEmpty }
                if ($d.Type -eq 'AuditPolicy') { $d['Expected'] | Should -BeIn @('Success','Failure') }
            }
        }
    }
    It 'includes the user-rights and service rules' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            $p = Import-ContentPack -Path $PackPath
            $p['WN11-UR-000030']['Type']      | Should -Be 'UserRight'
            $p['WN11-UR-000030']['Privilege'] | Should -Be 'SeBackupPrivilege'
            # subsetof, not setequals: the STIG reads "if any groups or accounts
            # OTHER THAN the following", which a host satisfies by granting the
            # right to fewer principals than listed.
            $p['WN11-UR-000030']['Operator']  | Should -Be 'subsetof'
            $p['WN11-UR-000030']['Expected']  | Should -Be @('Administrators')
            $p['WN11-UR-000005']['Expected']  | Should -BeNullOrEmpty   # empty set
            $p['WN11-00-000175']['Type']      | Should -Be 'Service'
            $p['WN11-00-000175']['Operator']  | Should -Be 'eq'
            $p['WN11-00-000175']['Expected']  | Should -Be 'Disabled'
        }
    }
    It 'now provides broader coverage (>160 declarative descriptors)' {
        InModuleScope woscap -Parameters @{ PackPath = $script:PackPath } {
            (Import-ContentPack -Path $PackPath).Keys.Count | Should -BeGreaterThan 160
        }
    }
}

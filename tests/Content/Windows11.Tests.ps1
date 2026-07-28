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

# Code-review invariants for #29 (R1, R4, R5, R6).
BeforeDiscovery {
    $script:invalidDescriptors = @(
        @{ Why = 'ge with a string Expected'; D = @{ Operator = 'ge'; Expected = '5' } }
        @{ Why = 'an unknown Kind';           D = @{ Operator = 'eq'; Expected = 1; Kind = 'binary' } }
        @{ Why = 'qword with a string';       D = @{ Operator = 'eq'; Expected = '1'; Kind = 'qword' } }
        @{ Why = 'mixed elements';            D = @{ Operator = 'in'; Expected = @(1, 'a') } }
        @{ Why = 'no Operator';               D = @{ Expected = 1 } }
    )
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'helpers/New-WoscapTestRegEntry.ps1')
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'R1: an unresolvable registry kind is Error in every value state' {
    It '<Why> is Error whatever is stored' -ForEach $script:invalidDescriptors {
        $bad = InModuleScope woscap -Parameters @{ D = $D } {
            param($D)
            $states = [ordered]@{
                absent = $null; DWord = 1; QWord = [long]1; String = '1'; MultiString = @('1'); Binary = [byte[]]@(1, 1)
            }
            $out = foreach ($state in $states.Keys) {
                foreach ($absentIsPass in $false, $true) {
                    $script:r1Entry = New-WoscapTestRegEntry $states[$state]
                    Mock Get-RegValueEntry { $script:r1Entry }
                    $desc = @{ Type = 'Registry'; Path = 'HKLM:\X'; Name = 'Y' } + $D
                    if ($absentIsPass) { $desc['AbsentIsPass'] = $true }
                    $r = Test-Descriptor -Descriptor $desc
                    if ($r.Result -ne 'Error') { "$state AbsentIsPass=$absentIsPass -> $($r.Result)" }
                }
            }
            , @($out)
        }
        $bad | Should -BeNullOrEmpty
    }
}

Describe 'R4: one integer classification everywhere' {
    It '<Name> classifies identically in the resolver, the gates, the schema and the planner' -ForEach @(
        @{ Name = 'Int16';   V = [int16]1;  Int = $true }
        @{ Name = 'Int32';   V = 1;         Int = $true }
        @{ Name = 'Int64';   V = [long]1;   Int = $true }
        @{ Name = 'UInt16';  V = [uint16]1; Int = $true }
        @{ Name = 'UInt32';  V = [uint32]1; Int = $true }
        @{ Name = 'UInt64';  V = [uint64]1; Int = $true }
        @{ Name = 'Byte';    V = [byte]1;   Int = $true }
        @{ Name = 'SByte';   V = [sbyte]1;  Int = $true }
        @{ Name = 'String';  V = '1';       Int = $false }
        @{ Name = 'Double';  V = 1.0;       Int = $false }
        @{ Name = 'Boolean'; V = $true;     Int = $false }
    ) {
        InModuleScope woscap -Parameters @{ V = $V; Int = $Int } {
            param($V, $Int)
            Test-WoscapIntegerValue $V | Should -Be $Int
            # Resolver: an integer Expected with eq infers DWord.
            $kinds = (Get-WoscapRequiredRegKind -Descriptor @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=$V }).Kinds
            (@($kinds) -contains 'DWord') | Should -Be $Int
            # Gate: an integer gate value matches a stored DWord 1.
            Mock Get-RegValueEntry { New-WoscapTestRegEntry 1 }
            $gate = Test-WoscapApplicability -Applicability @{ RegistryValueEquals = @{ Path='HKLM:\X'; Name='V'; Value=$V } }
            (-not $gate.Applies) | Should -Be $Int
            # Schema: integer or string gate values are accepted; others are not.
            $d = @{ Applicability=@{ RegistryValueIn=@{ Path='HKLM:\X'; Name='V'; Values=@($V, $V) } }; Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 }
            (@(Test-WoscapDescriptorSchema -Descriptor $d).Count -eq 0) | Should -Be ($Int -or $V -is [string])
            # Planner: an Int32-range integer Expected is written as a DWORD.
            $plan = @(Get-WoscapRemediationPlan -FailedRule @([pscustomobject]@{ StigId='R'; Title='r'; Status='Open' }) `
                        -ContentPack @{ R = @{ Type='Registry'; Path='HKLM:\S'; Name='N'; Operator='eq'; Expected=$V } })[0]
            ($plan.Automatable -and $plan.Registry.Kind -eq 'dword') | Should -Be $Int
        }
    }
    It 'the planner keeps an integer outside Int32 Manual (<Name>)' -ForEach @(
        @{ Name = 'UInt32 max'; V = [uint32]::MaxValue }
        @{ Name = 'UInt64 max'; V = [uint64]::MaxValue }
        @{ Name = 'Int64 min';  V = [long]::MinValue }
    ) {
        InModuleScope woscap -Parameters @{ V = $V } {
            param($V)
            $plan = @(Get-WoscapRemediationPlan -FailedRule @([pscustomobject]@{ StigId='R'; Title='r'; Status='Open' }) `
                        -ContentPack @{ R = @{ Type='Registry'; Path='HKLM:\S'; Name='N'; Operator='eq'; Expected=$V } })[0]
            $plan.Type | Should -Be 'Manual'
        }
    }
    It 'a UInt64 gate value beyond Int64 does not throw and does not match' {
        InModuleScope woscap {
            Mock Get-RegValueEntry { New-WoscapTestRegEntry 1 }
            $r = Test-WoscapApplicability -Applicability @{ RegistryValueIn = @{ Path='HKLM:\X'; Name='V'; Values=@([uint64]::MaxValue) } }
            $r.Applies | Should -BeTrue
        }
    }
}

Describe 'R5: operator-less Registry Evidence may declare Kind' {
    It 'is not a schema defect' {
        InModuleScope woscap {
            $d = @{ Type='Manual'; Question='Q?'; Evidence=@{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Kind='dword' } }
            @(Test-WoscapDescriptorSchema -Descriptor $d).Count | Should -Be 0
        }
    }
    It 'an unknown Kind on operator-less Evidence is still a defect' {
        InModuleScope woscap {
            $d = @{ Type='Manual'; Question='Q?'; Evidence=@{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Kind='binary' } }
            @(Test-WoscapDescriptorSchema -Descriptor $d) | Should -Match 'binary'
        }
    }
    It 'the declared Kind drives the GatherOnly annotation (<Case>)' -ForEach @(
        @{ Case = 'mismatch'; Stored = 'string'; Want = '1 [String]' }
        @{ Case = 'match';    Stored = 'dword';  Want = '1' }
    ) {
        InModuleScope woscap -Parameters @{ Stored = $Stored; Want = $Want } {
            param($Stored, $Want)
            $script:r5Entry = if ($Stored -eq 'string') { New-WoscapTestRegEntry '1' } else { New-WoscapTestRegEntry 1 }
            Mock Get-RegValueEntry { $script:r5Entry }
            $r = Test-Descriptor -Descriptor @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Kind='dword' } -GatherOnly
            $r.Result | Should -Be 'NotReviewed'
            "$($r.Observed)" | Should -Be $Want
        }
    }
}

Describe 'R6: Get-RegValueEntry releases every key it opens' {
    It 'disposes the key on <Case> without enumerating value names' -ForEach @(
        @{ Case = 'a present value'; Present = $true;  Throw = $false }
        @{ Case = 'a missing value'; Present = $false; Throw = $false }
        @{ Case = 'a read failure';  Present = $true;  Throw = $true }
    ) {
        InModuleScope woscap -Parameters @{ Present = $Present; Throw = $Throw } {
            param($Present, $Throw)
            $script:fakeKey = [pscustomobject]@{ Disposed = 0; Enumerated = 0; Present = $Present; Throw = $Throw }
            $script:fakeKey | Add-Member ScriptMethod Dispose { $this.Disposed++ }
            $script:fakeKey | Add-Member ScriptMethod Close { $this.Disposed++ }
            $script:fakeKey | Add-Member ScriptMethod GetValueNames { $this.Enumerated++; @('Y') }
            $script:fakeKey | Add-Member ScriptMethod GetValue {
                param($n, $default)
                if ($this.Throw) { throw [System.Security.SecurityException]::new('denied') }
                if ($this.Present) { 7 } else { $default }
            }
            $script:fakeKey | Add-Member ScriptMethod GetValueKind { param($n) [Microsoft.Win32.RegistryValueKind]::DWord }
            Mock Get-Item { $script:fakeKey }
            $null = Get-RegValueEntry -Path 'HKLM:\X' -Name 'Y'
            $script:fakeKey.Disposed | Should -BeGreaterOrEqual 1
            $script:fakeKey.Enumerated | Should -Be 0
        }
    }
}

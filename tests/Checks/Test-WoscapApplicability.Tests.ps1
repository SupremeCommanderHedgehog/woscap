BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'helpers/New-WoscapTestRegEntry.ps1')
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Test-WoscapApplicability' {
    BeforeEach { InModuleScope woscap { Clear-WoscapReadCache } }

    It 'applies when DomainJoined matches' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { $true } -ParameterFilter { $Fact -eq 'DomainJoined' }
            (Test-WoscapApplicability -Applicability @{ DomainJoined = $true }).Applies | Should -BeTrue
        }
    }
    It 'does not apply when DomainJoined differs, and states why' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { $false } -ParameterFilter { $Fact -eq 'DomainJoined' }
            $r = Test-WoscapApplicability -Applicability @{ DomainJoined = $true }
            $r.Applies | Should -BeFalse
            $r.Reason  | Should -Match 'not domain-joined'
        }
    }
    It 'applies when every predicate is satisfied' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { $true }
            (Test-WoscapApplicability -Applicability @{ DomainJoined = $true; TpmPresent = $true }).Applies | Should -BeTrue
        }
    }
    It 'does not apply when any predicate fails' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { $true }  -ParameterFilter { $Fact -eq 'DomainJoined' }
            Mock Get-WoscapMachineFact { $false } -ParameterFilter { $Fact -eq 'TpmPresent' }
            (Test-WoscapApplicability -Applicability @{ DomainJoined = $true; TpmPresent = $true }).Applies | Should -BeFalse
        }
    }
    It 'honours OsBuildBelow' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { 22631 } -ParameterFilter { $Fact -eq 'OsBuild' }
            (Test-WoscapApplicability -Applicability @{ OsBuildBelow = 26100 }).Applies | Should -BeTrue
            (Test-WoscapApplicability -Applicability @{ OsBuildBelow = 22000 }).Applies | Should -BeFalse
        }
    }
    It 'honours OsBuildAtLeast' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { 22631 } -ParameterFilter { $Fact -eq 'OsBuild' }
            (Test-WoscapApplicability -Applicability @{ OsBuildAtLeast = 22000 }).Applies | Should -BeTrue
            (Test-WoscapApplicability -Applicability @{ OsBuildAtLeast = 26100 }).Applies | Should -BeFalse
        }
    }
    It 'honours RegistryValueEquals' {
        InModuleScope woscap {
            Mock Get-RegValueEntry { New-WoscapTestRegEntry 2 }
            $a = @{ RegistryValueEquals = @{ Path='HKLM:\X'; Name='V'; Value=2 } }
            (Test-WoscapApplicability -Applicability $a).Applies | Should -BeFalse
            $b = @{ RegistryValueEquals = @{ Path='HKLM:\X'; Name='V'; Value=9 } }
            (Test-WoscapApplicability -Applicability $b).Applies | Should -BeTrue
        }
    }
    It 'honours RegistryValueIn: NA only when the value is one of the set' {
        InModuleScope woscap {
            $a = @{ RegistryValueIn = @{ Path='HKLM:\X'; Name='V'; Values=@('2', '3') } }
            Mock Get-RegValueEntry { New-WoscapTestRegEntry '3' }
            (Test-WoscapApplicability -Applicability $a).Applies | Should -BeFalse
            Mock Get-RegValueEntry { New-WoscapTestRegEntry '6' }
            (Test-WoscapApplicability -Applicability $a).Applies | Should -BeTrue
            Mock Get-RegValueEntry { New-WoscapTestRegEntry ' 3' }
            (Test-WoscapApplicability -Applicability $a).Applies | Should -BeTrue
            Mock Get-RegValueEntry { $null }
            (Test-WoscapApplicability -Applicability $a).Applies | Should -BeTrue
        }
    }
    It 'flags Unreadable when a RegistryValueIn gate cannot read the value' {
        InModuleScope woscap {
            Mock Get-RegValueEntry { New-WoscapUnreadable -Reason 'access denied' }
            $r = Test-WoscapApplicability -Applicability @{ RegistryValueIn = @{ Path='HKLM:\X'; Name='V'; Values=@(0, 1) } }
            $r.Unreadable | Should -BeTrue
            $r.Applies | Should -BeFalse
        }
    }
    It 'treats an unknown predicate as a hard error, not as applicable' {
        InModuleScope woscap {
            { Test-WoscapApplicability -Applicability @{ Nonsense = $true } } | Should -Throw
        }
    }
    It 'flags Unreadable rather than reporting a confident NA when a fact read fails' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { New-WoscapUnreadable -Reason 'cannot determine TpmPresent' }
            $r = Test-WoscapApplicability -Applicability @{ TpmPresent = $true }
            $r.Unreadable | Should -BeTrue
            $r.Applies    | Should -BeFalse
            $r.Reason     | Should -Match 'cannot determine'
        }
    }
    It 'flags Unreadable when an OsBuild gate cannot read the build' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { New-WoscapUnreadable -Reason 'cannot determine OsBuild' }
            (Test-WoscapApplicability -Applicability @{ OsBuildBelow = 26100 }).Unreadable | Should -BeTrue
        }
    }
    It 'flags Unreadable when a RegistryValueEquals gate cannot read the value' {
        InModuleScope woscap {
            Mock Get-RegValueEntry { New-WoscapUnreadable -Reason 'access denied' }
            $a = @{ RegistryValueEquals = @{ Path='HKLM:\X'; Name='V'; Value=2 } }
            (Test-WoscapApplicability -Applicability $a).Unreadable | Should -BeTrue
        }
    }
    It 'reports Unreadable false on a normal NA so NA stays distinguishable' {
        InModuleScope woscap {
            Mock Get-WoscapMachineFact { $false } -ParameterFilter { $Fact -eq 'DomainJoined' }
            $r = Test-WoscapApplicability -Applicability @{ DomainJoined = $true }
            $r.Applies    | Should -BeFalse
            $r.Unreadable | Should -BeFalse
        }
    }
}

Describe 'Get-WoscapMachineFact' {
    BeforeEach { InModuleScope woscap { Clear-WoscapReadCache } }

    It 'reports DomainJoined from Win32_ComputerSystem' {
        InModuleScope woscap {
            Mock Get-CimInstance { [pscustomobject]@{ PartOfDomain = $true } }
            Get-WoscapMachineFact -Fact 'DomainJoined' | Should -BeTrue
        }
    }
    It 'reads a fact once per scan' {
        InModuleScope woscap {
            $script:factHits = 0
            Mock Get-CimInstance { $script:factHits++; [pscustomobject]@{ PartOfDomain = $true } }
            $null = Get-WoscapMachineFact -Fact 'DomainJoined'
            $null = Get-WoscapMachineFact -Fact 'DomainJoined'
            $script:factHits | Should -Be 1
        }
    }
    It 'reports unreadable when a presence read fails' {
        InModuleScope woscap {
            # Previously $false, which made Test-WoscapApplicability mark the
            # rule Not Applicable - dropping it from scoring entirely and
            # asserting the host had no TPM.
            Mock Get-CimInstance { throw 'denied' }
            Test-WoscapUnreadable -Value (Get-WoscapMachineFact -Fact 'TpmPresent') | Should -BeTrue
        }
    }
    It 'reports unreadable when the OsBuild read fails' {
        InModuleScope woscap {
            Mock Get-CimInstance { throw 'denied' }
            Test-WoscapUnreadable -Value (Get-WoscapMachineFact -Fact 'OsBuild') | Should -BeTrue
        }
    }
    It 'rejects an unknown fact name' {
        InModuleScope woscap {
            { Get-WoscapMachineFact -Fact 'Bogus' } | Should -Throw
        }
    }
}

# Spec section 2 (#36): Installer key in either view; a denied read is unreadable, never absent.
Describe 'Get-WoscapMachineFact AcrobatUnifiedApp' {
    BeforeDiscovery {
        $script:unifiedCases = @(
            @{ Native = 'present'; Wow = 'absent';  Want = 'true' }
            @{ Native = 'absent';  Wow = 'present'; Want = 'true' }
            @{ Native = 'present'; Wow = 'present'; Want = 'true' }
            @{ Native = 'absent';  Wow = 'absent';  Want = 'false' }
            @{ Native = 'denied';  Wow = 'absent';  Want = 'unreadable' }
            @{ Native = 'absent';  Wow = 'denied';  Want = 'unreadable' }
            @{ Native = 'present'; Wow = 'denied';  Want = 'unreadable' }
        )
    }
    It 'native <Native>, Wow6432Node <Wow> gives <Want>' -ForEach $script:unifiedCases {
        InModuleScope woscap -Parameters @{ Native = $Native; Wow = $Wow; Want = $Want } {
            param($Native, $Wow, $Want)
            Clear-WoscapReadCache
            $script:keyState = @{
                'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'             = $Native
                'HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat\DC\Installer' = $Wow
            }
            Mock Get-Item {
                switch ($script:keyState[$LiteralPath]) {
                    'present' { [pscustomobject]@{ Name = $LiteralPath } }
                    'absent'  { throw [System.Management.Automation.ItemNotFoundException]::new('no key') }
                    'denied'  { throw [System.Security.SecurityException]::new('access denied') }
                    default   { throw "unexpected path $LiteralPath" }
                }
            }
            $fact = Get-WoscapMachineFact -Fact 'AcrobatUnifiedApp'
            switch ($Want) {
                'unreadable' { Test-WoscapUnreadable -Value $fact | Should -BeTrue }
                default      { $fact | Should -BeOfType [bool]; $fact | Should -Be ($Want -eq 'true') }
            }
        }
    }
    It 'reads the Installer keys once per scan' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            $script:keyHits = 0
            Mock Get-Item { $script:keyHits++; throw [System.Management.Automation.ItemNotFoundException]::new('no key') }
            $null = Get-WoscapMachineFact -Fact 'AcrobatUnifiedApp'
            $null = Get-WoscapMachineFact -Fact 'AcrobatUnifiedApp'
            $script:keyHits | Should -Be 2 -Because 'one read per view, then cached'
        }
    }
    It 'gates applicability: applies, NA with the spec reason, or unreadable' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            Mock Get-WoscapMachineFact { $true } -ParameterFilter { $Fact -eq 'AcrobatUnifiedApp' }
            (Test-WoscapApplicability -Applicability @{ AcrobatUnifiedApp = $true }).Applies | Should -BeTrue

            Mock Get-WoscapMachineFact { $false } -ParameterFilter { $Fact -eq 'AcrobatUnifiedApp' }
            $na = Test-WoscapApplicability -Applicability @{ AcrobatUnifiedApp = $true }
            $na.Applies | Should -BeFalse
            $na.Unreadable | Should -BeFalse
            $na.Reason | Should -Be 'Not applicable: the unified Adobe Acrobat app is not installed.'

            Mock Get-WoscapMachineFact { New-WoscapUnreadable -Reason 'cannot determine AcrobatUnifiedApp' } -ParameterFilter { $Fact -eq 'AcrobatUnifiedApp' }
            $u = Test-WoscapApplicability -Applicability @{ AcrobatUnifiedApp = $true }
            $u.Unreadable | Should -BeTrue
            $u.Applies | Should -BeFalse
        }
    }
    It 'is an accepted schema predicate' {
        InModuleScope woscap {
            $d = @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\X'; Name = 'Y'; Operator = 'eq'; Expected = 1 }
            @(Test-WoscapDescriptorSchema -Descriptor $d).Count | Should -Be 0
        }
    }
}

# Spec section 5 (#29): a gate matches only on a compatible kind, so a wrong-kind
# value can never make a rule Not Applicable.
Describe 'Registry applicability gates honour the value kind' {
    BeforeDiscovery {
        $script:gateCases = foreach ($gate in 'RegistryValueEquals', 'RegistryValueIn') {
            @{ Gate = $gate; Case = 'int gate, DWord equal';          GateValue = 1;   Stored = 'dword1';  Applies = $false }
            @{ Gate = $gate; Case = 'int gate, String "1"';           GateValue = 1;   Stored = 'string1'; Applies = $true }
            @{ Gate = $gate; Case = 'int gate, MultiString with 1';   GateValue = 1;   Stored = 'multi1';  Applies = $true }
            @{ Gate = $gate; Case = 'int gate, Binary';               GateValue = 1;   Stored = 'binary1'; Applies = $true }
            @{ Gate = $gate; Case = 'int gate, QWord equal';          GateValue = 1;   Stored = 'qword1';  Applies = $true }
            @{ Gate = $gate; Case = 'string gate, String equal';      GateValue = '1'; Stored = 'string1'; Applies = $false }
            @{ Gate = $gate; Case = 'string gate, ExpandString equal'; GateValue = '1'; Stored = 'expand1'; Applies = $false }
            @{ Gate = $gate; Case = 'string gate, DWord';             GateValue = '1'; Stored = 'dword1';  Applies = $true }
            @{ Gate = $gate; Case = 'absent';                         GateValue = 1;   Stored = 'absent';  Applies = $true }
            @{ Gate = $gate; Case = 'unreadable';                     GateValue = 1;   Stored = 'unreadable'; Applies = $false }
        }
    }
    It '<Gate>: <Case>' -ForEach $script:gateCases {
        InModuleScope woscap -Parameters @{ Gate = $Gate; GateValue = $GateValue; Stored = $Stored; Want = $Applies } {
            param($Gate, $GateValue, $Stored, $Want)
            Clear-WoscapReadCache
            $script:gateEntry = switch ($Stored) {
                'dword1'     { New-WoscapTestRegEntry 1 }
                'qword1'     { New-WoscapTestRegEntry ([long]1) }
                'string1'    { New-WoscapTestRegEntry '1' }
                'expand1'    { New-WoscapTestRegEntry '1' -Kind ExpandString }
                'multi1'     { New-WoscapTestRegEntry @('1') }
                'binary1'    { New-WoscapTestRegEntry ([byte[]]@(1)) }
                'absent'     { $null }
                'unreadable' { New-WoscapUnreadable -Reason 'access denied' }
            }
            Mock Get-RegValueEntry { $script:gateEntry }
            $arg = if ($Gate -eq 'RegistryValueEquals') { @{ Path='HKLM:\X'; Name='V'; Value=$GateValue } }
                   else { @{ Path='HKLM:\X'; Name='V'; Values=@($GateValue, $GateValue) } }
            $r = Test-WoscapApplicability -Applicability @{ $Gate = $arg }
            $r.Applies | Should -Be $Want
            $r.Unreadable | Should -Be ($Stored -eq 'unreadable')
        }
    }
}

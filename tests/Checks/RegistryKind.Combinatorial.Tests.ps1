# Spec invariant 8.1 (#29): generated over stored kind x operator x Expected shape x
# declared Kind x AbsentIsPass. One It per stored kind keeps the run lean.
BeforeDiscovery {
    $script:storedKinds = @('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary', 'absent', 'unreadable') |
        ForEach-Object { @{ Stored = $_ } }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'helpers/New-WoscapTestRegEntry.ps1')
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Registry checks honour the stored value kind (combinatorial)' {
    It 'stored <Stored>: wrong kind never passes; right kind compares as before' -ForEach $script:storedKinds {
        $failures = InModuleScope woscap -Parameters @{ Stored = $Stored } {
            param($Stored)
            # Every value would match Expected '1' / 1 / @('1') if kinds were ignored.
            $script:cellEntry = switch ($Stored) {
                'DWord'        { New-WoscapTestRegEntry 1 }
                'QWord'        { New-WoscapTestRegEntry ([long]1) }
                'String'       { New-WoscapTestRegEntry '1' }
                'ExpandString' { New-WoscapTestRegEntry '1' -Kind ExpandString }
                'MultiString'  { New-WoscapTestRegEntry @('1') }
                'Binary'       { New-WoscapTestRegEntry ([byte[]]@(1, 1)) }
                'absent'       { $null }
                'unreadable'   { New-WoscapUnreadable -Reason 'access denied' }
            }
            Mock Get-RegValueEntry { $script:cellEntry }
            $shapes = @{ int = 1; string = '1'; 'string[]' = @('1') }
            $out = New-Object System.Collections.Generic.List[string]
            $cells = 0
            foreach ($op in 'eq', 'ne', 'ge', 'le', 'in', 'notin', 'regex', 'setequals', 'includes', 'exists') {
                foreach ($shape in @($shapes.Keys)) {
                    foreach ($kind in 'none', 'dword', 'qword', 'string', 'multistring') {
                        foreach ($absentIsPass in $false, $true) {
                            $d = @{ Type = 'Registry'; Path = 'HKLM:\X'; Name = 'Y'; Operator = $op; Expected = $shapes[$shape] }
                            if ($kind -ne 'none') { $d['Kind'] = $kind }
                            if ($absentIsPass) { $d['AbsentIsPass'] = $true }
                            $required = Get-WoscapRequiredRegKind -Descriptor $d
                            if ($required.Error) { continue }   # the schema rejects these at load
                            $cells++
                            $cell = "op=$op shape=$shape Kind=$kind AbsentIsPass=$absentIsPass"
                            $r = Test-Descriptor -Descriptor $d
                            if ($Stored -eq 'unreadable') {
                                if ($r.Result -ne 'Error') { $out.Add("$cell -> $($r.Result), want Error") }
                                continue
                            }
                            if ($Stored -eq 'absent') {
                                $want = if ($absentIsPass) { 'Pass' }
                                        elseif (Compare-WoscapValue -Operator $op -Observed $null -Expected $d.Expected) { 'Pass' }
                                        else { 'Fail' }
                                if ($r.Result -ne $want) { $out.Add("$cell -> $($r.Result), want $want") }
                                continue
                            }
                            $compatible = ($required.Kinds -eq '*') -or (@($required.Kinds) -contains $Stored)
                            if (-not $compatible) {
                                if ($r.Result -ne 'Fail') { $out.Add("$cell -> $($r.Result), want Fail (incompatible)") }
                                elseif ("$($r.Observed)" -notmatch "^$Stored .*requires") {
                                    $out.Add("$cell -> Observed '$($r.Observed)' does not name the kind and requirement")
                                }
                                continue
                            }
                            $want = if (Compare-WoscapValue -Operator $op -Observed $script:cellEntry.Value -Expected $d.Expected) { 'Pass' } else { 'Fail' }
                            if ($r.Result -ne $want) { $out.Add("$cell -> $($r.Result), want $want (compatible)") }
                        }
                    }
                }
            }
            if ($cells -eq 0) { $out.Add('no cells generated') }
            , $out.ToArray()
        }
        $failures | Should -BeNullOrEmpty
    }
}

Describe 'Registry kind: GatherOnly and NameCase' {
    It 'GatherOnly reports a compatible value unchanged' {
        InModuleScope woscap {
            Mock Get-RegValueEntry { New-WoscapTestRegEntry 7 }
            $r = Test-Descriptor -Descriptor @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 } -GatherOnly
            $r.Result   | Should -Be 'NotReviewed'
            $r.Observed | Should -Be 7
        }
    }
    It 'GatherOnly appends the kind only when it is incompatible' {
        InModuleScope woscap {
            Mock Get-RegValueEntry { New-WoscapTestRegEntry '1' }
            $r = Test-Descriptor -Descriptor @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1 } -GatherOnly
            $r.Result   | Should -Be 'NotReviewed'
            $r.Observed | Should -Be '1 [String]'
        }
    }
    It 'reads with -ExactNameCase when NameCase is Exact' {
        InModuleScope woscap {
            Mock Get-RegValueEntry { $null }
            Mock Get-RegValueEntry { New-WoscapTestRegEntry 1 } -ParameterFilter { $ExactNameCase }
            $d = @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1; NameCase='Exact' }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
            $d.Remove('NameCase')
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail' -Because 'without NameCase the read is case-insensitive'
        }
    }
    It 'a wrong-case name under NameCase Exact reads as absent (AbsentIsPass honoured)' {
        InModuleScope woscap {
            Mock Get-RegValueEntry { $null } -ParameterFilter { $ExactNameCase }
            $d = @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='eq'; Expected=1; NameCase='Exact' }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail'
            $d['AbsentIsPass'] = $true
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Pass'
        }
    }
    It 'a descriptor whose kind cannot be resolved is an Error, not a verdict' {
        InModuleScope woscap {
            Mock Get-RegValueEntry { New-WoscapTestRegEntry '5' }
            $r = Test-Descriptor -Descriptor @{ Type='Registry'; Path='HKLM:\X'; Name='Y'; Operator='ge'; Expected='5' }
            $r.Result | Should -Be 'Error'
        }
    }
}

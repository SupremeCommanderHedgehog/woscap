BeforeDiscovery {
    $script:declaredCases = @(
        @{ Kind = 'dword';        Operator = 'eq';       Expected = 1;            Kinds = @('DWord') }
        @{ Kind = 'dword';        Operator = 'ge';       Expected = 5;            Kinds = @('DWord') }
        @{ Kind = 'qword';        Operator = 'eq';       Expected = [long]1;      Kinds = @('QWord') }
        @{ Kind = 'string';       Operator = 'eq';       Expected = 'x';          Kinds = @('String', 'ExpandString') }
        # Kind 'string' with an integer Expected: a REG_SZ holding a number.
        @{ Kind = 'string';       Operator = 'le';       Expected = 10;           Kinds = @('String', 'ExpandString') }
        @{ Kind = 'string';       Operator = 'in';       Expected = @('a', 'b');  Kinds = @('String', 'ExpandString') }
        @{ Kind = 'expandstring'; Operator = 'regex';    Expected = '^C:';        Kinds = @('ExpandString') }
        @{ Kind = 'multistring';  Operator = 'setequals'; Expected = @('a');      Kinds = @('MultiString') }
        @{ Kind = 'dword';        Operator = 'exists';   Expected = $true;        Kinds = @('DWord') }
    )
    $script:inferredCases = @(
        @{ Operator = 'exists'; Expected = $true; Kinds = '*' }
        @{ Operator = 'exists'; Expected = $false; Kinds = '*' }
    )
    foreach ($op in 'eq', 'ne', 'ge', 'le', 'in', 'notin') {
        $script:inferredCases += @{ Operator = $op; Expected = 1;                 Kinds = @('DWord') }
        $script:inferredCases += @{ Operator = $op; Expected = @(1, [long]2);     Kinds = @('DWord') }
    }
    foreach ($op in 'eq', 'ne', 'in', 'notin', 'regex') {
        $script:inferredCases += @{ Operator = $op; Expected = 'x';               Kinds = @('String', 'ExpandString') }
        $script:inferredCases += @{ Operator = $op; Expected = @('x', 'y');       Kinds = @('String', 'ExpandString') }
    }
    foreach ($op in 'setequals', 'subsetof', 'supersetof', 'sequence', 'includes') {
        $script:inferredCases += @{ Operator = $op; Expected = @('a', 'b');       Kinds = @('MultiString') }
        $script:inferredCases += @{ Operator = $op; Expected = 1;                 Kinds = @('MultiString') }
    }
    # At least one Error per rule.
    $script:errorCases = @(
        @{ Why = 'unknown Kind';                    D = @{ Kind = 'binary'; Operator = 'eq'; Expected = 1 } }
        @{ Why = 'qword with a string Expected';    D = @{ Kind = 'qword'; Operator = 'eq'; Expected = '1' } }
        @{ Why = 'dword with a string Expected';    D = @{ Kind = 'dword'; Operator = 'in'; Expected = @('1') } }
        @{ Why = 'dword with a set operator';       D = @{ Kind = 'dword'; Operator = 'setequals'; Expected = @(1) } }
        @{ Why = 'string with a set operator';      D = @{ Kind = 'string'; Operator = 'includes'; Expected = 'a' } }
        @{ Why = 'string with ge on a string';      D = @{ Kind = 'string'; Operator = 'ge'; Expected = '5' } }
        @{ Why = 'string with regex on an int';     D = @{ Kind = 'string'; Operator = 'regex'; Expected = 5 } }
        @{ Why = 'multistring with eq';             D = @{ Kind = 'multistring'; Operator = 'eq'; Expected = 'a' } }
        @{ Why = 'ge with a string Expected';       D = @{ Operator = 'ge'; Expected = '5' } }
        @{ Why = 'le with a string Expected';       D = @{ Operator = 'le'; Expected = '5' } }
        @{ Why = 'regex with an int Expected';      D = @{ Operator = 'regex'; Expected = 5 } }
        @{ Why = 'mixed int and string elements';   D = @{ Operator = 'in'; Expected = @(1, 'a') } }
        @{ Why = 'an empty Expected';               D = @{ Operator = 'in'; Expected = @() } }
        @{ Why = 'a null Expected';                 D = @{ Operator = 'eq'; Expected = $null } }
        @{ Why = 'a boolean Expected';              D = @{ Operator = 'eq'; Expected = $true } }
        @{ Why = 'no Operator';                     D = @{ Expected = 1 } }
        @{ Why = 'an unknown Operator';             D = @{ Operator = 'bogus'; Expected = 1 } }
    )
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapRequiredRegKind' {
    It 'declared Kind <Kind> with <Operator> requires <Kinds>' -ForEach $script:declaredCases {
        $d = @{ Type = 'Registry'; Path = 'HKLM:\X'; Name = 'Y'; Kind = $Kind; Operator = $Operator; Expected = $Expected }
        $r = InModuleScope woscap -Parameters @{ D = $d } { param($D) Get-WoscapRequiredRegKind -Descriptor $D }
        $r.Error | Should -BeNullOrEmpty
        @($r.Kinds) | Should -Be @($Kinds)
    }
    It 'inferred: <Operator> with Expected <Expected> requires <Kinds>' -ForEach $script:inferredCases {
        $d = @{ Type = 'Registry'; Path = 'HKLM:\X'; Name = 'Y'; Operator = $Operator; Expected = $Expected }
        $r = InModuleScope woscap -Parameters @{ D = $d } { param($D) Get-WoscapRequiredRegKind -Descriptor $D }
        $r.Error | Should -BeNullOrEmpty
        @($r.Kinds) | Should -Be @($Kinds)
    }
    It 'rejects <Why>' -ForEach $script:errorCases {
        $d = @{ Type = 'Registry'; Path = 'HKLM:\X'; Name = 'Y' } + $D
        $r = InModuleScope woscap -Parameters @{ D = $d } { param($D) Get-WoscapRequiredRegKind -Descriptor $D }
        $r.Error | Should -Not -BeNullOrEmpty
        $r.Kinds | Should -BeNullOrEmpty
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Compare-WoscapValue' {
    It '<Op> (<Observed> vs <Expected>) => <Result>' -TestCases @(
        @{ Op = 'eq';       Observed = 1;               Expected = 1;             Result = $true }
        @{ Op = 'eq';       Observed = 1;               Expected = 2;             Result = $false }
        @{ Op = 'ne';       Observed = 'a';             Expected = 'b';           Result = $true }
        @{ Op = 'ne';       Observed = 'a';             Expected = 'a';           Result = $false }
        @{ Op = 'ge';       Observed = 15;              Expected = 14;            Result = $true }
        @{ Op = 'ge';       Observed = 13;              Expected = 14;            Result = $false }
        @{ Op = 'ge';       Observed = $null;           Expected = 14;            Result = $false }
        @{ Op = 'ge';       Observed = 15;              Expected = $null;         Result = $false }
        @{ Op = 'le';       Observed = 30;             Expected = 30;            Result = $true }
        @{ Op = 'le';       Observed = 31;             Expected = 30;            Result = $false }
        @{ Op = 'le';       Observed = $null;           Expected = 14;            Result = $false }
        @{ Op = 'le';       Observed = 15;              Expected = $null;         Result = $false }
        @{ Op = 'in';       Observed = 2;               Expected = @(1,2,3);      Result = $true }
        @{ Op = 'in';       Observed = 9;               Expected = @(1,2,3);      Result = $false }
        @{ Op = 'includes'; Observed = @('Success','Failure'); Expected = 'Failure'; Result = $true }
        @{ Op = 'includes'; Observed = @('Success');    Expected = 'Failure';     Result = $false }
        @{ Op = 'regex';    Observed = 'v1.2.3';        Expected = '^v\d+';       Result = $true }
        @{ Op = 'regex';    Observed = 'x';             Expected = '^v\d+';       Result = $false }
        @{ Op = 'exists';   Observed = 'anything';      Expected = $true;         Result = $true }
        @{ Op = 'exists';   Observed = $null;           Expected = $true;         Result = $false }
        @{ Op = 'exists';   Observed = $null;           Expected = $false;        Result = $true }
        @{ Op = 'setequals'; Observed = @('S-1-5-32-544');            Expected = @('S-1-5-32-544');            Result = $true }
        @{ Op = 'setequals'; Observed = @('S-1-5-32-544','S-1-5-19'); Expected = @('S-1-5-19','S-1-5-32-544'); Result = $true }
        @{ Op = 'setequals'; Observed = @('S-1-5-32-544','S-1-5-19'); Expected = @('S-1-5-32-544');            Result = $false }
        @{ Op = 'setequals'; Observed = @('S-1-5-32-544');            Expected = @('S-1-5-32-544','S-1-5-19'); Result = $false }
        @{ Op = 'setequals'; Observed = @();                          Expected = @();                          Result = $true }
        @{ Op = 'setequals'; Observed = @('S-1-5-32-544');            Expected = @();                          Result = $false }
    ) {
        InModuleScope woscap -Parameters @{ Op=$Op; Observed=$Observed; Expected=$Expected; Result=$Result } {
            Compare-WoscapValue -Operator $Op -Observed $Observed -Expected $Expected | Should -Be $Result
        }
    }
    It 'throws on an unknown operator (fail closed)' {
        InModuleScope woscap {
            { Compare-WoscapValue -Operator 'bogus' -Observed 1 -Expected 1 } |
                Should -Throw -ExpectedMessage '*does not belong to the set*'
        }
    }

    Context 'sequence' {
        It 'passes on identical order' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator sequence -Observed @('NistP384','NistP256') -Expected @('NistP384','NistP256') | Should -BeTrue
            }
        }
        It 'fails on reversed order' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator sequence -Observed @('NistP256','NistP384') -Expected @('NistP384','NistP256') | Should -BeFalse
            }
        }
        It 'fails on a length mismatch' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator sequence -Observed @('NistP384') -Expected @('NistP384','NistP256') | Should -BeFalse
            }
        }
        It 'fails when observed is null' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator sequence -Observed $null -Expected @('NistP384') | Should -BeFalse
            }
        }
        It 'passes when both sides are empty' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator sequence -Observed @() -Expected @() | Should -BeTrue
            }
        }
    }

    Context 'subsetof' {
        It 'passes when observed is a proper subset' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator subsetof -Observed @('S-1-5-32-544') -Expected @('S-1-5-32-544','S-1-5-32-555') | Should -BeTrue
            }
        }
        It 'passes when the sets are equal' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator subsetof -Observed @('A','B') -Expected @('B','A') | Should -BeTrue
            }
        }
        It 'fails when observed carries an extra principal' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator subsetof -Observed @('A','Z') -Expected @('A','B') | Should -BeFalse
            }
        }
        It 'passes when observed is empty (nobody holds the right)' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator subsetof -Observed @() -Expected @('A') | Should -BeTrue
            }
        }
        It 'passes when observed is null' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator subsetof -Observed $null -Expected @('A') | Should -BeTrue
            }
        }
    }

    Context 'supersetof' {
        It 'passes when every required principal is present' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator supersetof -Observed @('A','B','C') -Expected @('A','B') | Should -BeTrue
            }
        }
        It 'fails when a required principal is missing' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator supersetof -Observed @('A') -Expected @('A','B') | Should -BeFalse
            }
        }
        It 'fails when observed is empty and something is required' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator supersetof -Observed @() -Expected @('A') | Should -BeFalse
            }
        }
        It 'passes when nothing is required' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator supersetof -Observed @() -Expected @() | Should -BeTrue
            }
        }
    }

    Context 'exists with collections' {
        It 'treats an empty collection as absent' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator exists -Observed @() -Expected $true | Should -BeFalse
            }
        }
        It 'treats an empty collection as satisfying a must-not-exist check' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator exists -Observed @() -Expected $false | Should -BeTrue
            }
        }
        It 'treats a populated collection as present' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator exists -Observed @('Defender') -Expected $true | Should -BeTrue
            }
        }
        It 'treats an empty string as present (it is a real reading)' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator exists -Observed '' -Expected $true | Should -BeTrue
            }
        }
    }

    Context 'notin' {
        It 'passes when observed is outside the set' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator notin -Observed 3 -Expected @(1,2) | Should -BeTrue
            }
        }
        It 'fails when observed is in the set' {
            InModuleScope woscap {
                Compare-WoscapValue -Operator notin -Observed 2 -Expected @(1,2) | Should -BeFalse
            }
        }
    }
}

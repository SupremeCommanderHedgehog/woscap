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
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-CheckEval' {
    BeforeAll {
        $script:Rules = @(
            [pscustomobject]@{ GroupId='V-1'; RuleId='SV-1r1_rule'; StigId='WNTEST-00-000010'; Severity='medium'; Title='Has check'; Cci=@('CCI-1'); Benchmark='B'; BenchmarkVersion='1' }
            [pscustomobject]@{ GroupId='V-2'; RuleId='SV-2r1_rule'; StigId='WNTEST-00-000099'; Severity='high';   Title='No check'; Cci=@();        Benchmark='B'; BenchmarkVersion='1' }
        )
    }
    It 'evaluates a rule that has a passing check -> NotAFinding' {
        InModuleScope woscap -Parameters @{ Rules = $script:Rules } {
            Mock Get-RegValue { 1 }
            $pack = @{ 'WNTEST-00-000010' = @{ Type='Registry'; Path='HKLM:\X'; Name='Foo'; Operator='eq'; Expected=1 } }
            $res = Invoke-CheckEval -Rules $Rules -ContentPack $pack
            $withCheck = $res | Where-Object StigId -eq 'WNTEST-00-000010'
            $withCheck.Status   | Should -Be 'NotAFinding'
            $withCheck.Severity | Should -Be 'medium'
            $withCheck.Cci      | Should -Contain 'CCI-1'
        }
    }
    It 'marks a rule with no authored check as Not_Reviewed' {
        InModuleScope woscap -Parameters @{ Rules = $script:Rules } {
            $pack = @{ 'WNTEST-00-000010' = @{ Type='Registry'; Path='HKLM:\X'; Name='Foo'; Operator='eq'; Expected=1 } }
            $res = Invoke-CheckEval -Rules $Rules -ContentPack $pack
            $noCheck = $res | Where-Object StigId -eq 'WNTEST-00-000099'
            $noCheck.Status | Should -Be 'Not_Reviewed'
        }
    }
    It 'maps a failing check -> Open with observed value recorded' {
        InModuleScope woscap -Parameters @{ Rules = $script:Rules } {
            Mock Get-RegValue { 0 }
            $pack = @{ 'WNTEST-00-000010' = @{ Type='Registry'; Path='HKLM:\X'; Name='Foo'; Operator='eq'; Expected=1 } }
            $res = Invoke-CheckEval -Rules $Rules -ContentPack $pack
            $r = $res | Where-Object StigId -eq 'WNTEST-00-000010'
            $r.Status   | Should -Be 'Open'
            $r.Observed | Should -Be 0
        }
    }
    It 'returns one result per input rule' {
        InModuleScope woscap -Parameters @{ Rules = $script:Rules } {
            (Invoke-CheckEval -Rules $Rules -ContentPack @{}).Count | Should -Be 2
        }
    }
    It 'propagates CheckText/FixText/Discussion from the rule metadata' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ GroupId='V-1'; RuleId='SV-1r1_rule'; StigId='WNTEST-00-000010'; Severity='medium'; Title='T'; Cci=@(); Benchmark='B'; BenchmarkVersion='1'; CheckText='CC'; FixText='FF'; Discussion='DD' })
            $res = Invoke-CheckEval -Rules $rules -ContentPack @{}
            $res.CheckText  | Should -Be 'CC'
            $res.FixText    | Should -Be 'FF'
            $res.Discussion | Should -Be 'DD'
        }
    }
    It 'treats a rule with a null StigId as Not_Reviewed (fail closed)' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ GroupId='V-9'; RuleId='SV-9r1_rule'; StigId=$null; Severity='low'; Title='No version'; Cci=@(); Benchmark='B'; BenchmarkVersion='1' })
            $res = Invoke-CheckEval -Rules $rules -ContentPack @{ 'WNTEST-00-000010' = @{ Type='Registry'; Path='HKLM:\X'; Name='Foo'; Operator='eq'; Expected=1 } }
            @($res).Count | Should -Be 1
            $res.Status   | Should -Be 'Not_Reviewed'
        }
    }
}

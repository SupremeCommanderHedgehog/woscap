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
    It 'propagates the Group title (SRG) from the rule metadata into the result' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ GroupId='V-1'; GroupTitle='SRG-OS-000480'; RuleId='SV-1r1_rule'; StigId='WNTEST-00-000010'; Severity='medium'; Title='T'; Cci=@(); Benchmark='B'; BenchmarkVersion='1' })
            $res = Invoke-CheckEval -Rules $rules -ContentPack @{}
            $res.GroupTitle | Should -Be 'SRG-OS-000480'
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
    It 'NotApplicable exception -> Not_Applicable, no check run' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ GroupId='V-1'; RuleId='SV-1r1_rule'; StigId='S1'; Severity='medium'; Title='T'; Cci=@(); Benchmark='B'; BenchmarkVersion='1' })
            $pack = @{ 'S1' = @{ Type='Registry'; Path='HKLM:\X'; Name='Foo'; Operator='eq'; Expected=1 } }
            Mock Get-RegValue { throw 'should not be called' }
            $prof = @{ 'S1' = @{ Type='NotApplicable'; Justification='n/a here'; Author='jd' } }
            $r = Invoke-CheckEval -Rules $rules -ContentPack $pack -ExceptionProfile $prof
            $r.Status         | Should -Be 'Not_Applicable'
            $r.Exception.Type | Should -Be 'NotApplicable'
            $r.Comments       | Should -Be 'n/a here'
        }
    }
    It 'Exclude exception -> Not_Reviewed, no check run' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ GroupId='V-1'; RuleId='SV-1r1_rule'; StigId='S1'; Severity='medium'; Title='T'; Cci=@(); Benchmark='B'; BenchmarkVersion='1' })
            $pack = @{ 'S1' = @{ Type='Registry'; Path='HKLM:\X'; Name='Foo'; Operator='eq'; Expected=1 } }
            $prof = @{ 'S1' = @{ Type='Exclude'; Justification='out of band' } }
            $r = Invoke-CheckEval -Rules $rules -ContentPack $pack -ExceptionProfile $prof
            $r.Status         | Should -Be 'Not_Reviewed'
            $r.Exception.Type | Should -Be 'Exclude'
        }
    }
    It 'AcceptedRisk keeps a failing rule Open (never a pass) and tags it' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ GroupId='V-1'; RuleId='SV-1r1_rule'; StigId='S1'; Severity='high'; Title='T'; Cci=@(); Benchmark='B'; BenchmarkVersion='1' })
            $pack = @{ 'S1' = @{ Type='Registry'; Path='HKLM:\X'; Name='Foo'; Operator='eq'; Expected=1 } }
            Mock Get-RegValue { 0 }
            $prof = @{ 'S1' = @{ Type='AcceptedRisk'; Justification='comp control' } }
            $r = Invoke-CheckEval -Rules $rules -ContentPack $pack -ExceptionProfile $prof
            $r.Status         | Should -Be 'Open'
            $r.Exception.Type | Should -Be 'AcceptedRisk'
        }
    }
    It 'Override changes Expected and re-evaluates' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ GroupId='V-1'; RuleId='SV-1r1_rule'; StigId='S1'; Severity='medium'; Title='T'; Cci=@(); Benchmark='B'; BenchmarkVersion='1' })
            $pack = @{ 'S1' = @{ Type='Registry'; Path='HKLM:\X'; Name='Foo'; Operator='eq'; Expected=1 } }
            Mock Get-RegValue { 5 }
            $prof = @{ 'S1' = @{ Type='Override'; Justification='org value'; Expected=5 } }
            $r = Invoke-CheckEval -Rules $rules -ContentPack $pack -ExceptionProfile $prof
            $r.Status         | Should -Be 'NotAFinding'
            $r.Exception.Type | Should -Be 'Override'
        }
    }
    It 'Override can lower Severity' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ GroupId='V-1'; RuleId='SV-1r1_rule'; StigId='S1'; Severity='high'; Title='T'; Cci=@(); Benchmark='B'; BenchmarkVersion='1' })
            $pack = @{ 'S1' = @{ Type='Registry'; Path='HKLM:\X'; Name='Foo'; Operator='eq'; Expected=1 } }
            Mock Get-RegValue { 1 }
            $prof = @{ 'S1' = @{ Type='Override'; Justification='downgrade'; Severity='low' } }
            $r = Invoke-CheckEval -Rules $rules -ContentPack $pack -ExceptionProfile $prof
            $r.Severity | Should -Be 'low'
        }
    }
    It 'an expired exception is ignored — rule evaluated normally (fail closed)' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ GroupId='V-1'; RuleId='SV-1r1_rule'; StigId='S1'; Severity='medium'; Title='T'; Cci=@(); Benchmark='B'; BenchmarkVersion='1' })
            $pack = @{ 'S1' = @{ Type='Registry'; Path='HKLM:\X'; Name='Foo'; Operator='eq'; Expected=1 } }
            Mock Get-RegValue { 0 }
            $prof = @{ 'S1' = @{ Type='NotApplicable'; Justification='x'; Expires='2000-01-01' } }
            $r = Invoke-CheckEval -Rules $rules -ContentPack $pack -ExceptionProfile $prof -ReferenceDate ([datetime]'2026-07-11') -WarningAction SilentlyContinue
            $r.Status    | Should -Be 'Open'
            $r.Exception | Should -BeNullOrEmpty
        }
    }
    It 'still works with no exception profile (backward compatible)' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ GroupId='V-1'; RuleId='SV-1r1_rule'; StigId='S1'; Severity='medium'; Title='T'; Cci=@(); Benchmark='B'; BenchmarkVersion='1' })
            Mock Get-RegValue { 1 }
            $pack = @{ 'S1' = @{ Type='Registry'; Path='HKLM:\X'; Name='Foo'; Operator='eq'; Expected=1 } }
            (Invoke-CheckEval -Rules $rules -ContentPack $pack).Status | Should -Be 'NotAFinding'
        }
    }
    It 'emits a Write-Progress record per rule while evaluating' {
        InModuleScope woscap -Parameters @{ Rules = $script:Rules } {
            Mock Write-Progress { }
            Invoke-CheckEval -Rules $Rules -ContentPack @{} | Out-Null
            # One per rule (2 rules), plus is allowed to emit a final -Completed record.
            Should -Invoke Write-Progress -Times 2 -Scope It -ParameterFilter { -not $Completed }
        }
    }
    It 'ignores an invalid Override Severity (keeps rule severity, does not abort)' {
        InModuleScope woscap {
            $rules = @([pscustomobject]@{ GroupId='V-1'; RuleId='SV-1r1_rule'; StigId='S1'; Severity='high'; Title='T'; Cci=@(); Benchmark='B'; BenchmarkVersion='1' })
            $pack = @{ 'S1' = @{ Type='Registry'; Path='HKLM:\X'; Name='Foo'; Operator='eq'; Expected=1 } }
            Mock Get-RegValue { 1 }
            $prof = @{ 'S1' = @{ Type='Override'; Justification='bad sev'; Severity='CAT-I' } }
            $r = Invoke-CheckEval -Rules $rules -ContentPack $pack -ExceptionProfile $prof -WarningAction SilentlyContinue
            $r.Severity | Should -Be 'high'      # invalid override ignored -> rule severity kept
            $r.Status   | Should -Be 'NotAFinding'
        }
    }
}

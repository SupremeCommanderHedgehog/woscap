BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapComplianceMetric' {
    It 'counts open findings by CAT and computes compliance %' {
        InModuleScope woscap {
            $res = @(
                [pscustomobject]@{ Host = 'H'; Status = 'Open';         Severity = 'high';   Exception = $null },
                [pscustomobject]@{ Host = 'H'; Status = 'Open';         Severity = 'medium'; Exception = $null },
                [pscustomobject]@{ Host = 'H'; Status = 'NotAFinding';  Severity = 'low';    Exception = $null },
                [pscustomobject]@{ Host = 'H'; Status = 'Not_Applicable'; Severity = 'low';  Exception = $null }
            )
            $m = Get-WoscapComplianceMetric -Result $res
            $m['woscap.open.cat1'] | Should -Be 1
            $m['woscap.open.cat2'] | Should -Be 1
            $m['woscap.open.cat3'] | Should -Be 0
            $m['woscap.findings.total'] | Should -Be 4
            # evaluated = 4 - 1 NA = 3; NotAFinding = 1 -> 33.33
            [math]::Round($m['woscap.compliance.pct'], 2) | Should -Be 33.33
        }
    }
    It 'counts risk-accepted exceptions separately' {
        InModuleScope woscap {
            $res = @(
                [pscustomobject]@{ Host = 'H'; Status = 'Open'; Severity = 'high'; Exception = [pscustomobject]@{ Type = 'AcceptedRisk' } }
            )
            $m = Get-WoscapComplianceMetric -Result $res
            $m['woscap.exceptions.count'] | Should -Be 1
            $m['woscap.exceptions.riskaccepted'] | Should -Be 1
        }
    }
    It 'reports 100% compliance when every evaluated rule passes' {
        InModuleScope woscap {
            $res = @([pscustomobject]@{ Host = 'H'; Status = 'NotAFinding'; Severity = 'low'; Exception = $null })
            (Get-WoscapComplianceMetric -Result $res)['woscap.compliance.pct'] | Should -Be 100
        }
    }
    It 'reports 0% (not false-green) for an empty result set' {
        InModuleScope woscap {
            $m = Get-WoscapComplianceMetric -Result @()
            $m['woscap.compliance.pct'] | Should -Be 0
            $m['woscap.findings.total'] | Should -Be 0
        }
    }
    It 'reports 0% (not false-green) when every rule is Not_Applicable' {
        InModuleScope woscap {
            $res = @(
                [pscustomobject]@{ Host = 'H'; Status = 'Not_Applicable'; Severity = 'low'; Exception = $null },
                [pscustomobject]@{ Host = 'H'; Status = 'Not_Applicable'; Severity = 'low'; Exception = $null }
            )
            $m = Get-WoscapComplianceMetric -Result $res
            $m['woscap.compliance.pct'] | Should -Be 0
            $m['woscap.findings.total'] | Should -Be 2
        }
    }
    It 'does not throw and counts a projected object lacking an Exception property' {
        InModuleScope woscap {
            $res = @(
                [pscustomobject]@{ Host = 'H'; Status = 'Open'; Severity = 'high' } |
                    Select-Object Host, Status, Severity
            )
            { Get-WoscapComplianceMetric -Result $res } | Should -Not -Throw
            $m = Get-WoscapComplianceMetric -Result $res
            $m['woscap.findings.total'] | Should -Be 1
            $m['woscap.open.cat1'] | Should -Be 1
            $m['woscap.exceptions.count'] | Should -Be 0
        }
    }
}

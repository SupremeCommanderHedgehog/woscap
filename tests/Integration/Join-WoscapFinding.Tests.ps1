BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Join-WoscapFinding' {
    It 'links a finding to a rule that shares a CCI, and preserves an unmatched finding' {
        InModuleScope woscap {
            $rules = @(
                [pscustomobject]@{ Host = '10.0.0.5'; RuleId = 'SV-1'; StigId = 'WN-1'; Cci = @('CCE-24913-4', 'CCI-000366') },
                [pscustomobject]@{ Host = '10.0.0.5'; RuleId = 'SV-2'; StigId = 'WN-2'; Cci = @('CCI-000999') }
            )
            $findings = @(
                [pscustomobject]@{ Host = '10.0.0.5'; Id = 'F1'; Cve = @('CVE-2017-0143'); Cce = @('CCE-24913-4'); Cci = @() },
                [pscustomobject]@{ Host = '10.0.0.5'; Id = 'F2'; Cve = @('CVE-2016-2183'); Cce = @(); Cci = @() }
            )
            $view = Join-WoscapFinding -Results $rules -Findings $findings
            @($view.Results).Count | Should -Be 2
            @($view.Findings).Count | Should -Be 2
            @($view.Links).Count | Should -Be 1
            $view.Links[0].RuleId | Should -Be 'SV-1'
            $view.Links[0].FindingId | Should -Be 'F1'
            $view.Links[0].MatchedOn | Should -Be 'CCE-24913-4'
        }
    }
    It 'does not mutate the input RuleResults' {
        InModuleScope woscap {
            $rule = [pscustomobject]@{ Host = 'H'; RuleId = 'R'; StigId = 'S'; Cci = @('CCI-1') }
            $find = [pscustomobject]@{ Host = 'H'; Id = 'F'; Cve = @(); Cce = @(); Cci = @('CCI-1') }
            $null = Join-WoscapFinding -Results @($rule) -Findings @($find)
            $rule.PSObject.Properties.Name | Should -Not -Contain 'RelatedFindings'
        }
    }
    It 'only links findings on the same host' {
        InModuleScope woscap {
            $rule = [pscustomobject]@{ Host = 'H1'; RuleId = 'R'; StigId = 'S'; Cci = @('CCI-1') }
            $find = [pscustomobject]@{ Host = 'H2'; Id = 'F'; Cve = @(); Cce = @(); Cci = @('CCI-1') }
            (Join-WoscapFinding -Results @($rule) -Findings @($find)).Links.Count | Should -Be 0
        }
    }
    It 'correlates an IP-host finding to a computername rule via HostMap' {
        InModuleScope woscap {
            $rule = [pscustomobject]@{ Host = 'SRV01'; RuleId = 'SV-1'; StigId = 'WN-1'; Cci = @('CCI-000366') }
            $find = [pscustomobject]@{ Host = '10.0.0.5'; Id = 'F1'; Cve = @(); Cce = @(); Cci = @('CCI-000366') }
            $view = Join-WoscapFinding -Results @($rule) -Findings @($find) -HostMap @{ '10.0.0.5' = 'SRV01' }
            @($view.Links).Count | Should -Be 1
            $view.Links[0].RuleId | Should -Be 'SV-1'
            $view.Links[0].Host   | Should -Be 'SRV01'
        }
    }
    It 'still correlates when host strings already match (no HostMap)' {
        InModuleScope woscap {
            $rule = [pscustomobject]@{ Host = 'H'; RuleId = 'R'; StigId = 'S'; Cci = @('CCI-1') }
            $find = [pscustomobject]@{ Host = 'H'; Id = 'F'; Cve = @(); Cce = @(); Cci = @('CCI-1') }
            (Join-WoscapFinding -Results @($rule) -Findings @($find)).Links.Count | Should -Be 1
        }
    }
    It 'surfaces an unresolvable-host finding but produces no link' {
        InModuleScope woscap {
            $rule = [pscustomobject]@{ Host = 'SRV01'; RuleId = 'R'; StigId = 'S'; Cci = @('CCI-1') }
            $find = [pscustomobject]@{ Host = '10.0.0.99'; Id = 'F'; Cve = @(); Cce = @(); Cci = @('CCI-1') }
            $view = Join-WoscapFinding -Results @($rule) -Findings @($find)
            @($view.Findings).Count | Should -Be 1
            @($view.Links).Count    | Should -Be 0
        }
    }
    It 'reverse-resolves the finding host when -ResolveDns is set (mocked)' {
        InModuleScope woscap {
            Mock Resolve-WoscapReverseDns { 'SRV01' }
            $rule = [pscustomobject]@{ Host = 'SRV01'; RuleId = 'R'; StigId = 'S'; Cci = @('CCI-1') }
            $find = [pscustomobject]@{ Host = '10.0.0.5'; Id = 'F'; Cve = @(); Cce = @(); Cci = @('CCI-1') }
            (Join-WoscapFinding -Results @($rule) -Findings @($find) -ResolveDns).Links.Count | Should -Be 1
        }
    }
    It 'correlates a short-name rule to an FQDN finding host' {
        InModuleScope woscap {
            $rule = [pscustomobject]@{ Host = 'SRV01'; RuleId = 'R'; StigId = 'S'; Cci = @('CCI-1') }
            $find = [pscustomobject]@{ Host = 'SRV01.corp.example'; Id = 'F'; Cve = @(); Cce = @(); Cci = @('CCI-1') }
            (Join-WoscapFinding -Results @($rule) -Findings @($find)).Links.Count | Should -Be 1
        }
    }
    It 'does not link two entries that both lack a Host' {
        InModuleScope woscap {
            $rule = [pscustomobject]@{ Host = $null; RuleId = 'R'; StigId = 'S'; Cci = @('CCI-1') }
            $find = [pscustomobject]@{ Host = $null; Id = 'F'; Cve = @(); Cce = @(); Cci = @('CCI-1') }
            (Join-WoscapFinding -Results @($rule) -Findings @($find)).Links.Count | Should -Be 0
        }
    }
    It 'links only the rule whose resolved host matches, across multiple rules' {
        InModuleScope woscap {
            $rules = @(
                [pscustomobject]@{ Host = 'SRV01'; RuleId = 'SV-A'; StigId = 'S'; Cci = @('CCI-1') },
                [pscustomobject]@{ Host = 'SRV02'; RuleId = 'SV-B'; StigId = 'S'; Cci = @('CCI-1') }
            )
            $find = [pscustomobject]@{ Host = '10.0.0.5'; Id = 'F'; Cve = @(); Cce = @(); Cci = @('CCI-1') }
            $view = Join-WoscapFinding -Results $rules -Findings @($find) -HostMap @{ '10.0.0.5' = 'SRV01' }
            @($view.Links).Count | Should -Be 1
            $view.Links[0].RuleId | Should -Be 'SV-A'
        }
    }
    It 'reverse-resolves a repeated finding host only once (memoized)' {
        InModuleScope woscap {
            Mock Resolve-WoscapReverseDns { 'SRV01' }
            $rule = [pscustomobject]@{ Host = 'SRV01'; RuleId = 'R'; StigId = 'S'; Cci = @('CCI-1') }
            $finds = @(
                [pscustomobject]@{ Host = '10.0.0.5'; Id = 'F1'; Cve = @(); Cce = @(); Cci = @('CCI-1') },
                [pscustomobject]@{ Host = '10.0.0.5'; Id = 'F2'; Cve = @(); Cce = @(); Cci = @('CCI-1') }
            )
            $view = Join-WoscapFinding -Results @($rule) -Findings $finds -ResolveDns
            @($view.Links).Count | Should -Be 2
            Should -Invoke Resolve-WoscapReverseDns -Times 1 -Exactly
        }
    }
}

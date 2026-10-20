BeforeDiscovery {
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-WoscapGuiRemediate' -Skip:(-not $script:IsSta) {
    BeforeEach {
        InModuleScope woscap {
            $me = $env:COMPUTERNAME
            $script:local1 = [pscustomobject]@{ Host = $me;    StigId = 'R-1'; Severity = 'high';   Status = 'Open';        Title = 'r1'; Exception = $null }
            $script:local2 = [pscustomobject]@{ Host = $me;    StigId = 'R-2'; Severity = 'medium'; Status = 'Open';        Title = 'r2'; Exception = $null }
            $script:clean  = [pscustomobject]@{ Host = $me;    StigId = 'R-3'; Severity = 'low';    Status = 'NotAFinding'; Title = 'r3'; Exception = $null }
            $script:remote = [pscustomobject]@{ Host = 'SRV9'; StigId = 'R-4'; Severity = 'high';   Status = 'Open';        Title = 'r4'; Exception = $null }
            $script:plan = @(
                [pscustomobject]@{ StigId = 'R-1'; StigIds = @('R-1'); Title = 'r1'; Action = 'a1'; State = 'Planned'; Detail = '' }
                [pscustomobject]@{ StigId = 'R-2'; StigIds = @('R-2'); Title = 'r2'; Action = 'a2'; State = 'Planned'; Detail = '' }
            )
            $script:applied = @([pscustomobject]@{ StigId = 'R-1'; StigIds = @('R-1'); Title = 'r1'; Action = 'a1'; State = 'Applied'; After = 'NotAFinding'; Detail = '' })
            $script:previewParams = $null; $script:applyParams = $null
            $script:form = New-WoscapMainForm
            foreach ($r in $script:local1, $script:local2, $script:clean, $script:remote) { $script:form.Tag['Results'].Add($r) }
            $script:form.Tag['Benchmark'].SelectedItem = 'Windows11'
        }
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'previews only local Open findings with -WhatIf -Quiet and the Scan tab benchmark' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Invoke-WoscapGuiScan { $script:previewParams = $ScanParameters } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:previewParams['Result'] | ForEach-Object StigId) | Should -Be @('R-1', 'R-2')
            $script:previewParams['WhatIf']    | Should -BeTrue
            $script:previewParams['Quiet']     | Should -BeTrue
            $script:previewParams['Benchmark'] | Should -Be 'Windows11'
            $script:previewParams.ContainsKey('Force')       | Should -BeFalse
            $script:previewParams.ContainsKey('ContentPath') | Should -BeFalse
        }
    }

    It 'passes the Scan tab content path when set' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Invoke-WoscapGuiScan { $script:previewParams = $ScanParameters } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            $script:form.Tag['ContentPath'].Text = 'D:\pack'
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:previewParams['ContentPath'] | Should -Be 'D:\pack'
        }
    }

    It 'uses the grid selection when there is one' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @($script:local2) }
            Mock Invoke-WoscapGuiScan { $script:previewParams = $ScanParameters } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:previewParams['Result'] | ForEach-Object StigId) | Should -Be @('R-2')
        }
    }

    It 'disables Run and Remediate while the preview runs' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Invoke-WoscapGuiScan { } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:form.Tag['Run'].Enabled           | Should -BeFalse
            $script:form.Tag['MenuRun'].Enabled       | Should -BeFalse
            $script:form.Tag['Remediate'].Enabled     | Should -BeFalse
            $script:form.Tag['MenuRemediate'].Enabled | Should -BeFalse
        }
    }

    It 'applies exactly the findings whose StigIds were ticked, with -Force and without -WhatIf' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Test-WoscapGuiElevated { $true }
            Mock Show-WoscapGuiRemediationDialog { @('R-2') }
            Mock Show-WoscapGuiRemediationReport { 'Close' }
            Mock Invoke-WoscapGuiScan {
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnComplete -Results $script:plan }
                else { $script:applyParams = $ScanParameters; & $OnComplete -Results $script:applied }
            } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:applyParams['Result'] | ForEach-Object StigId) | Should -Be @('R-2')
            $script:applyParams['Force'] | Should -BeTrue
            $script:applyParams.ContainsKey('WhatIf') | Should -BeFalse
            Should -Invoke Show-WoscapGuiRemediationDialog -Times 1 -Exactly -ParameterFilter { $Elevated -eq $true }
            Should -Invoke Show-WoscapGuiRemediationReport -Times 1 -Exactly
            $script:form.Tag['Run'].Enabled       | Should -BeTrue
            $script:form.Tag['Remediate'].Enabled | Should -BeTrue
        }
    }

    It 'never applies when the dialog is cancelled' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Test-WoscapGuiElevated { $true }
            Mock Show-WoscapGuiRemediationDialog { }
            Mock Show-WoscapGuiRemediationReport { 'Close' }
            $script:calls = 0
            Mock Invoke-WoscapGuiScan {
                $script:calls++
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnComplete -Results $script:plan }
            } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:calls | Should -Be 1 -Because 'only the preview may run'
            Should -Not -Invoke Show-WoscapGuiRemediationReport
            $script:form.Tag['Run'].Enabled | Should -BeTrue
        }
    }

    It 'shows a message and starts nothing when no local Open finding qualifies' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @($script:remote, $script:clean) }
            Mock Invoke-WoscapGuiScan { }
            $script:shown = @()
            Mock Show-WoscapGuiMessage { $script:shown += $Text }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            Should -Not -Invoke Invoke-WoscapGuiScan
            $script:shown[0] | Should -Match '1 remote'
            $script:shown[0] | Should -Match '1 not Open'
        }
    }

    It 'offers the re-scan through the normal Run path' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Test-WoscapGuiElevated { $true }
            Mock Show-WoscapGuiRemediationDialog { @('R-1') }
            Mock Show-WoscapGuiRemediationReport { 'Rescan' }
            Mock Invoke-WoscapGuiRun { }
            Mock Invoke-WoscapGuiScan {
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnComplete -Results $script:plan }
                else { & $OnComplete -Results $script:applied }
            } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            Should -Invoke Invoke-WoscapGuiRun -Times 1 -Exactly
        }
    }

    It 'does not re-enable Run when an apply-time outcome arrives after the re-scan started' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Test-WoscapGuiElevated { $true }
            Mock Show-WoscapGuiRemediationDialog { @('R-1') }
            Mock Show-WoscapGuiRemediationReport { 'Rescan' }
            Mock Show-WoscapGuiMessage { }
            # Stand-in for a started scan: Run goes busy.
            Mock Invoke-WoscapGuiRun { Set-WoscapGuiActionEnabled -Tag $Tag -Action Run -Enabled $false; $Tag['Status'].Text = 'Scanning...' }
            Mock Invoke-WoscapGuiScan {
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnComplete -Results $script:plan }
                else {
                    # Runner order: OnComplete first, then the classified outcome.
                    & $OnComplete -Results $script:applied
                    & $OnWarning -Message 'w' -Count 1
                    & $OnError -Message 'late'
                }
            } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:form.Tag['Run'].Enabled | Should -BeFalse
            $script:form.Tag['Status'].Text | Should -Be 'Scanning...'
        }
    }

    It 'says fixes were applied when a step after delivering apply results fails' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Test-WoscapGuiElevated { $true }
            Mock Show-WoscapGuiRemediationDialog { @('R-1') }
            Mock Show-WoscapGuiRemediationReport { throw 'report broke' }
            $script:shown = @()
            Mock Show-WoscapGuiMessage { $script:shown += $Text }
            Mock Invoke-WoscapGuiScan {
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnComplete -Results $script:plan }
                else {
                    # Mirrors the runner's tick catch: a throwing OnComplete is routed to OnError.
                    try { & $OnComplete -Results $script:applied } catch { & $OnError -Message $_.Exception.Message }
                }
            } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Not -Match 'Remediation failed'
            $script:shown[0] | Should -Match 'already applied'
            $script:shown[0] | Should -Match 'report broke'
            $script:form.Tag['Run'].Enabled       | Should -BeTrue
            $script:form.Tag['Remediate'].Enabled | Should -BeTrue
        }
    }

    It 'says fixes were applied when the report throws straight out of the runner call' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Test-WoscapGuiElevated { $true }
            Mock Show-WoscapGuiRemediationDialog { @('R-1') }
            Mock Show-WoscapGuiRemediationReport { throw 'report broke' }
            $script:shown = @()
            Mock Show-WoscapGuiMessage { $script:shown += $Text }
            Mock Invoke-WoscapGuiScan {
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnComplete -Results $script:plan }
                else { & $OnComplete -Results $script:applied }
            } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Match 'already applied'
            $script:shown[0] | Should -Not -Match 'Remediation failed|Could not start'
            $script:form.Tag['Run'].Enabled | Should -BeTrue
        }
    }

    It 'keeps the Remediation failed wording when apply delivers no results' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Test-WoscapGuiElevated { $true }
            Mock Show-WoscapGuiRemediationDialog { @('R-1') }
            Mock Show-WoscapGuiRemediationReport { 'Close' }
            $script:shown = @()
            Mock Show-WoscapGuiMessage { $script:shown += $Text }
            Mock Invoke-WoscapGuiScan {
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnComplete -Results $script:plan }
                else { & $OnComplete -Results @(); & $OnError -Message 'access denied' }
            } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:shown[-1] | Should -Match 'Remediation failed: access denied'
        }
    }

    It 'applies only valid local Open findings even if the dialog returns other StigIds' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Test-WoscapGuiElevated { $true }
            Mock Show-WoscapGuiRemediationDialog { @('R-4', 'R-3', 'R-1') }
            Mock Show-WoscapGuiRemediationReport { 'Close' }
            Mock Invoke-WoscapGuiScan {
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnComplete -Results $script:plan }
                else { $script:applyParams = $ScanParameters; & $OnComplete -Results $script:applied }
            } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:applyParams['Result'] | ForEach-Object StigId) | Should -Be @('R-1')
        }
    }

    It 'applies the preview-time findings even if Results change before apply' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Test-WoscapGuiElevated { $true }
            Mock Show-WoscapGuiRemediationDialog {
                $script:form.Tag['Results'].Clear()
                $script:form.Tag['Results'].Add([pscustomobject]@{ Host = $env:COMPUTERNAME; StigId = 'R-9'; Severity = 'high'; Status = 'Open'; Title = 'r9'; Exception = $null })
                @('R-1', 'R-2', 'R-9')
            }
            Mock Show-WoscapGuiRemediationReport { 'Close' }
            Mock Invoke-WoscapGuiScan {
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnComplete -Results $script:plan }
                else { $script:applyParams = $ScanParameters; & $OnComplete -Results $script:applied }
            } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:applyParams['Result'] | ForEach-Object StigId) | Should -Be @('R-1', 'R-2')
            @($script:applyParams['Result'])[0] | Should -Be $script:local1
        }
    }

    It 'never applies when the confirmation dialog throws, and re-enables Run and Remediate' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Test-WoscapGuiElevated { $true }
            Mock Show-WoscapGuiRemediationDialog { throw 'dialog broke' }
            Mock Show-WoscapGuiRemediationReport { 'Close' }
            Mock Show-WoscapGuiMessage { }
            $script:calls = 0
            Mock Invoke-WoscapGuiScan {
                $script:calls++
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnComplete -Results $script:plan }
            } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:calls | Should -Be 1 -Because 'only the preview may run'
            Should -Not -Invoke Show-WoscapGuiRemediationReport
            $script:form.Tag['Run'].Enabled           | Should -BeTrue
            $script:form.Tag['MenuRun'].Enabled       | Should -BeTrue
            $script:form.Tag['Remediate'].Enabled     | Should -BeTrue
            $script:form.Tag['MenuRemediate'].Enabled | Should -BeTrue
        }
    }

    It 'reports a preview failure and re-enables Run and Remediate' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Invoke-WoscapGuiScan { & $OnError -Message 'pack missing' } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            $script:shown = @()
            Mock Show-WoscapGuiMessage { $script:shown += $Text }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:shown[0] | Should -Match 'Remediation failed: pack missing'
            $script:form.Tag['Run'].Enabled       | Should -BeTrue
            $script:form.Tag['Remediate'].Enabled | Should -BeTrue
        }
    }

    It 'recovers when the background run cannot start' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Invoke-WoscapGuiScan { throw 'no runspace' } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Mock Show-WoscapGuiMessage { }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly
            $script:form.Tag['Run'].Enabled | Should -BeTrue
        }
    }
}

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
            $script:none = [pscustomobject]@{ Kind = 'None'; Message = ''; Count = 0 }
            $script:form = New-WoscapMainForm
            foreach ($r in $script:local1, $script:local2, $script:clean, $script:remote) { $script:form.Tag['Results'].Add($r) }
            $script:form.Tag['Benchmark'].SelectedItem = 'Windows11'
            # Stand-in for a completed scan: its context, and the rows as the grid shows them.
            $script:form.Tag['ResultsContext'] = @{ Benchmark = 'Windows11'; ContentPath = '' }
            Update-WoscapGuiView -Tag $script:form.Tag
            # Never let an unexpected path pop a real MessageBox; tests that inspect it re-mock.
            Mock Show-WoscapGuiMessage { }
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

    It 'passes the scanned content path when set' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Invoke-WoscapGuiScan { $script:previewParams = $ScanParameters } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            $script:form.Tag['ResultsContext'] = @{ Benchmark = 'Windows11'; ContentPath = 'D:\pack' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:previewParams['ContentPath'] | Should -Be 'D:\pack'
        }
    }

    It 'uses the grid selection when there is one' {
        InModuleScope woscap {
            Mock Get-WoscapGuiSelectedResult { @($script:local2) }
            $script:form.Tag['GridSelectionDeliberate'] = $true
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
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results $script:plan -Outcome $script:none }
                else { $script:applyParams = $ScanParameters; & $OnComplete -Results $script:applied }
            } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:applyParams['Result'] | ForEach-Object StigId) | Should -Be @('R-2')
            $script:applyParams['Force'] | Should -BeTrue
            $script:applyParams.ContainsKey('WhatIf') | Should -BeFalse
            Should -Invoke Show-WoscapGuiRemediationDialog -Times 1 -Exactly -ParameterFilter { $Elevated -eq $true }
            Should -Invoke Show-WoscapGuiRemediationReport -Times 1 -Exactly
            $script:form.Tag['Run'].Enabled       | Should -BeTrue
            $script:form.Tag['Remediate'].Enabled | Should -BeFalse -Because 'the grid predates the applied fix'
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
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results $script:plan -Outcome $script:none }
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
            $script:form.Tag['GridSelectionDeliberate'] = $true
            Mock Invoke-WoscapGuiScan { }
            $script:shown = @()
            Mock Show-WoscapGuiMessage { $script:shown += $Text }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            Should -Not -Invoke Invoke-WoscapGuiScan
            $script:shown[0] | Should -Match '1 remote'
            $script:shown[0] | Should -Match '1 not Open'
        }
    }

    It 'never remediates an Override finding and reports how many were skipped' {
        InModuleScope woscap {
            $ov = [pscustomobject]@{ Host = $env:COMPUTERNAME; StigId = 'R-5'; Severity = 'high'; Status = 'Open'; Title = 'r5'
                Exception = [pscustomobject]@{ Type = 'Override'; Justification = 'org value' } }
            Mock Get-WoscapGuiSelectedResult { @($script:local1, $ov) }
            $script:form.Tag['GridSelectionDeliberate'] = $true
            Mock Test-WoscapGuiElevated { $true }
            $script:dialogSummary = $null
            Mock Show-WoscapGuiRemediationDialog { $script:dialogSummary = $Summary }
            Mock Invoke-WoscapGuiScan {
                $script:previewParams = $ScanParameters
                & $OnSettled -Results $script:plan -Outcome $script:none
            } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:previewParams['Result'] | ForEach-Object StigId) | Should -Be @('R-1')
            $script:dialogSummary | Should -Match '1 finding\(s\) with an Override exception skipped'
        }
    }

    It 'counts Override findings when nothing is left to remediate' {
        InModuleScope woscap {
            $ov = [pscustomobject]@{ Host = $env:COMPUTERNAME; StigId = 'R-5'; Severity = 'high'; Status = 'Open'; Title = 'r5'
                Exception = [pscustomobject]@{ Type = 'Override' } }
            Mock Get-WoscapGuiSelectedResult { @($ov) }
            $script:form.Tag['GridSelectionDeliberate'] = $true
            Mock Invoke-WoscapGuiScan { }
            $script:shown = @()
            Mock Show-WoscapGuiMessage { $script:shown += $Text }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            Should -Not -Invoke Invoke-WoscapGuiScan
            $script:shown[0] | Should -Match '1 with an Override exception'
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
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results $script:plan -Outcome $script:none }
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
            Mock Invoke-WoscapGuiRun { Set-WoscapGuiActionEnabled -Tag $Tag -Action Run -Enabled $false; $Tag['Status'].Text = 'Scanning...'; $true }
            Mock Invoke-WoscapGuiScan {
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results $script:plan -Outcome $script:none }
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
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results $script:plan -Outcome $script:none }
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
            $script:form.Tag['Remediate'].Enabled | Should -BeFalse -Because 'the grid predates the applied fix'
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
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results $script:plan -Outcome $script:none }
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
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results $script:plan -Outcome $script:none }
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
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results $script:plan -Outcome $script:none }
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
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results $script:plan -Outcome $script:none }
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
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results $script:plan -Outcome $script:none }
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

Describe 'Invoke-WoscapGuiRemediate targeting' -Skip:(-not $script:IsSta) {
    BeforeEach {
        InModuleScope woscap {
            $me = $env:COMPUTERNAME
            $script:scanRows = @(
                [pscustomobject]@{ Host = $me;    StigId = 'R-1'; Severity = 'high';   Status = 'Open';        Title = 'r1'; Exception = $null }
                [pscustomobject]@{ Host = $me;    StigId = 'R-2'; Severity = 'medium'; Status = 'Open';        Title = 'r2'; Exception = $null }
                [pscustomobject]@{ Host = $me;    StigId = 'R-3'; Severity = 'low';    Status = 'NotAFinding'; Title = 'r3'; Exception = $null }
                [pscustomobject]@{ Host = 'SRV9'; StigId = 'R-4'; Severity = 'high';   Status = 'Open';        Title = 'r4'; Exception = $null }
            )
            $script:previewParams = $null
            # One runner stand-in: a scan delivers scanRows; a remediation preview is captured, never run.
            Mock Invoke-WoscapGuiScan {
                if ($Command -eq 'Invoke-WoscapRemediation') { $script:previewParams = $ScanParameters }
                else { & $OnComplete -Results $script:scanRows }
            }
            Mock Show-WoscapGuiMessage { }
            $script:form = New-WoscapMainForm
            $script:form.Tag['Xccdf'].Text = (Get-Module woscap).Path
        }
    }
    AfterEach { InModuleScope woscap { $script:form.Close(); $script:form.Dispose() } }

    It 'targets every visible local Open row on a shown, freshly scanned grid with no user selection' {
        InModuleScope woscap {
            $script:form.Show(); [System.Windows.Forms.Application]::DoEvents()
            Invoke-WoscapGuiRun -Tag $script:form.Tag
            [System.Windows.Forms.Application]::DoEvents()
            $script:form.Tag['Grid'].SelectedRows.Count | Should -BeGreaterThan 0 -Because 'WinForms auto-selects a row on a shown grid'
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:previewParams['Result'] | ForEach-Object StigId) | Should -Be @('R-1', 'R-2')
        }
    }

    It 'uses a selection the operator made with the keyboard' {
        InModuleScope woscap {
            $script:form.Show(); [System.Windows.Forms.Application]::DoEvents()
            Invoke-WoscapGuiRun -Tag $script:form.Tag
            [System.Windows.Forms.Application]::DoEvents()
            $grid = $script:form.Tag['Grid']
            $grid.CurrentCell = $grid.Rows[0].Cells[0]
            $onKeyDown = [System.Windows.Forms.DataGridView].GetMethod('OnKeyDown', [System.Reflection.BindingFlags]'NonPublic, Instance')
            [void]$onKeyDown.Invoke($grid, @([System.Windows.Forms.KeyEventArgs]::new([System.Windows.Forms.Keys]::Down)))
            [System.Windows.Forms.Application]::DoEvents()
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:previewParams['Result'] | ForEach-Object StigId) | Should -Be @('R-2')
        }
    }

    It 'uses a selection the operator made with the mouse' {
        InModuleScope woscap {
            $script:form.Show(); [System.Windows.Forms.Application]::DoEvents()
            Invoke-WoscapGuiRun -Tag $script:form.Tag
            [System.Windows.Forms.Application]::DoEvents()
            $grid = $script:form.Tag['Grid']
            $grid.ClearSelection(); $grid.Rows[1].Selected = $true
            $click = [System.Windows.Forms.DataGridViewCellMouseEventArgs]::new(0, 1, 1, 1,
                [System.Windows.Forms.MouseEventArgs]::new([System.Windows.Forms.MouseButtons]::Left, 1, 1, 1, 0))
            # The protected virtual overload; a private one makes GetMethod ambiguous.
            $onCellMouseDown = [System.Windows.Forms.DataGridView].GetMethods([System.Reflection.BindingFlags]'NonPublic, Instance') |
                Where-Object { $_.Name -eq 'OnCellMouseDown' -and $_.IsFamily } | Select-Object -First 1
            [void]$onCellMouseDown.Invoke($grid, @($click))
            $script:form.Tag['GridSelectionDeliberate'] | Should -BeTrue
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:previewParams['Result'] | ForEach-Object StigId) | Should -Be @('R-2')
        }
    }

    It 'does not treat a <Button> mouse press on a row as a deliberate selection' -ForEach @(
        @{ Button = 'Right' }, @{ Button = 'Middle' }
    ) {
        InModuleScope woscap -Parameters @{ Button = $Button } {
            param($Button)
            $script:form.Show(); [System.Windows.Forms.Application]::DoEvents()
            Invoke-WoscapGuiRun -Tag $script:form.Tag
            [System.Windows.Forms.Application]::DoEvents()
            $grid = $script:form.Tag['Grid']
            $click = [System.Windows.Forms.DataGridViewCellMouseEventArgs]::new(0, 1, 1, 1,
                [System.Windows.Forms.MouseEventArgs]::new([System.Windows.Forms.MouseButtons]$Button, 1, 1, 1, 0))
            $onCellMouseDown = [System.Windows.Forms.DataGridView].GetMethods([System.Reflection.BindingFlags]'NonPublic, Instance') |
                Where-Object { $_.Name -eq 'OnCellMouseDown' -and $_.IsFamily } | Select-Object -First 1
            [void]$onCellMouseDown.Invoke($grid, @($click))
            $script:form.Tag['GridSelectionDeliberate'] | Should -BeFalse
        }
    }

    It 'forgets a deliberate selection when a filter rebuilds the grid' {
        InModuleScope woscap {
            Invoke-WoscapGuiRun -Tag $script:form.Tag
            $script:form.Tag['GridSelectionDeliberate'] = $true
            $script:form.Tag['FilterStatus'].SelectedItem = 'Open'
            $script:form.Tag['GridSelectionDeliberate'] | Should -BeFalse
        }
    }

    It 'targets only the rows the filters leave visible' {
        InModuleScope woscap {
            Invoke-WoscapGuiRun -Tag $script:form.Tag
            $script:form.Tag['FilterSeverity'].SelectedItem = 'high'
            $script:form.Tag['Grid'].Rows.Count | Should -Be 2 -Because 'R-1 and R-4 are high'
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:previewParams['Result'] | ForEach-Object StigId) | Should -Be @('R-1')
        }
    }

    It 'uses the Benchmark and ContentPath of the scan that produced the results, not the controls at click time' {
        InModuleScope woscap {
            $script:form.Tag['Benchmark'].SelectedItem = 'Edge'
            $script:form.Tag['ContentPath'].Text = $TestDrive
            Invoke-WoscapGuiRun -Tag $script:form.Tag
            $script:form.Tag['Benchmark'].SelectedItem = 'Windows11'
            $script:form.Tag['ContentPath'].Text = ''
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:previewParams['Benchmark']   | Should -Be 'Edge'
            $script:previewParams['ContentPath'] | Should -Be $TestDrive
        }
    }

    It 'starts nothing when no scan produced the displayed results' {
        InModuleScope woscap {
            foreach ($r in $script:scanRows) { $script:form.Tag['Results'].Add($r) }
            Update-WoscapGuiView -Tag $script:form.Tag
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            Should -Invoke Invoke-WoscapGuiScan -Times 0 -Exactly -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly
        }
    }

    It 'Invoke-WoscapGuiRun returns true only when it started a scan' {
        InModuleScope woscap {
            @(Invoke-WoscapGuiRun -Tag $script:form.Tag) | Should -Be @($true)
            $script:form.Tag['Xccdf'].Text = ''
            @(Invoke-WoscapGuiRun -Tag $script:form.Tag) | Should -Be @($false)
            $script:form.Tag['Xccdf'].Text = (Get-Module woscap).Path
            Mock Invoke-WoscapGuiScan { throw 'no runspace' } -ParameterFilter { $Command -ne 'Invoke-WoscapRemediation' }
            @(Invoke-WoscapGuiRun -Tag $script:form.Tag) | Should -Be @($false)
        }
    }

    It 'forgets the scan context when a scan fails' {
        InModuleScope woscap {
            Invoke-WoscapGuiRun -Tag $script:form.Tag
            Mock Invoke-WoscapGuiScan { & $OnError -Message 'boom' } -ParameterFilter { $Command -ne 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRun -Tag $script:form.Tag
            $script:form.Tag['ResultsContext'] | Should -BeNullOrEmpty
        }
    }
}

Describe 'Invoke-WoscapGuiRemediate outcomes' -Skip:(-not $script:IsSta) {
    BeforeEach {
        InModuleScope woscap {
            $me = $env:COMPUTERNAME
            $script:form = New-WoscapMainForm
            foreach ($r in @(
                [pscustomobject]@{ Host = $me; StigId = 'R-1'; Severity = 'high';   Status = 'Open'; Title = 'r1'; Exception = $null }
                [pscustomobject]@{ Host = $me; StigId = 'M-1'; Severity = 'medium'; Status = 'Open'; Title = 'm1'; Exception = $null }
            )) { $script:form.Tag['Results'].Add($r) }
            $script:form.Tag['ResultsContext'] = @{ Benchmark = 'Windows11'; ContentPath = '' }
            Update-WoscapGuiView -Tag $script:form.Tag
            $script:plan = @(
                [pscustomobject]@{ StigId = 'R-1'; StigIds = @('R-1'); Title = 'r1'; Action = 'a1'; State = 'Planned'; Detail = '' }
                [pscustomobject]@{ StigId = 'M-1'; StigIds = @('M-1'); Title = 'm1'; Action = 'Manual remediation required'; State = 'Manual'; Detail = 'svc' }
            )
            $script:applied = @([pscustomobject]@{ StigId = 'R-1'; StigIds = @('R-1'); Title = 'r1'; Action = 'a1'; State = 'Applied'; After = 'NotAFinding'; Detail = '' })
            $script:failed  = @([pscustomobject]@{ StigId = 'R-1'; StigIds = @('R-1'); Title = 'r1'; Action = 'a1'; State = 'Failed'; After = ''; Detail = 'denied' })
            $script:applyResults = $script:applied
            $script:previewWarning = $null
            $script:previewError = $null
            $script:applyOutcome = $null
            $script:reported = $null
            $script:shown = @()
            Mock Show-WoscapGuiMessage { $script:shown += $Text }
            Mock Test-WoscapGuiElevated { $true }
            Mock Show-WoscapGuiRemediationDialog { @('R-1') }
            Mock Show-WoscapGuiRemediationReport { $script:reported = $Result; 'Close' }
            # Runner order: OnComplete first, then the classified outcome, then OnSettled.
            Mock Invoke-WoscapGuiScan {
                if ($ScanParameters.ContainsKey('WhatIf')) {
                    $kind = if ($script:previewWarning) { 'Warning' } else { 'None' }
                    $outcome = [pscustomobject]@{ Kind = $kind; Message = [string]$script:previewWarning; Count = 2 }
                    if ($script:previewError) {
                        $outcome = [pscustomobject]@{ Kind = 'Error'; Message = $script:previewError; Count = 1 }
                        & $OnError -Message $script:previewError
                    }
                    & $OnSettled -Results $script:plan -Outcome $outcome
                } else {
                    try { & $OnComplete -Results $script:applyResults } catch { & $OnError -Message $_.Exception.Message; return }
                    if ($script:applyOutcome -eq 'Warning') { & $OnWarning -Message 'apply-w' -Count 1 }
                }
            } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
        }
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'tells the operator the grid predates the fixes when the report is closed without re-scan' {
        InModuleScope woscap {
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:form.Tag['Status'].Text | Should -Match 're-scan'
        }
    }

    It 'keeps the re-scan notice when a late apply warning arrives' {
        InModuleScope woscap {
            $script:applyOutcome = 'Warning'
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:form.Tag['Status'].Text | Should -Match '1 warning'
            $script:form.Tag['Status'].Text | Should -Match 're-scan'
        }
    }

    It 'handles a late apply warning normally when the re-scan could not start' {
        InModuleScope woscap {
            Mock Show-WoscapGuiRemediationReport { 'Rescan' }
            $script:applyOutcome = 'Warning'
            $script:form.Tag['Xccdf'].Text = ''   # real Run refuses to start without an XCCDF
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:shown | Should -Contain 'Select a valid XCCDF (.xml) file before running.'
            $script:form.Tag['Status'].Text | Should -Match 'Remediation done \(1 warning'
            $script:form.Tag['StatusTip'].GetToolTip($script:form.Tag['Status']) | Should -Match 'apply-w'
            $script:form.Tag['Run'].Enabled | Should -BeTrue
        }
    }

    It 'does not claim fixes were applied when none reached State Applied' {
        InModuleScope woscap {
            $script:applyResults = $script:failed
            Mock Show-WoscapGuiRemediationReport { throw 'report broke' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Not -Match 'already applied'
            $script:shown[0] | Should -Match 'report broke'
            $script:form.Tag['Status'].Text | Should -Not -Match 're-scan'
        }
    }

    It 'surfaces preview warnings on the status line and tooltip when the dialog is cancelled' {
        InModuleScope woscap {
            Mock Show-WoscapGuiRemediationDialog { }
            $script:previewWarning = 'preview-w'
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:form.Tag['Status'].Text | Should -Match 'cancelled'
            $script:form.Tag['Status'].Text | Should -Match 'Preview: 2 warning'
            $script:form.Tag['StatusTip'].GetToolTip($script:form.Tag['Status']) | Should -Match 'preview-w'
        }
    }

    It 'shows preview warnings in the confirmation dialog, before the operator decides' {
        InModuleScope woscap {
            $script:previewWarning = 'preview-w'
            $script:dialogSummary = $null
            Mock Show-WoscapGuiRemediationDialog { $script:dialogSummary = $Summary }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiRemediationDialog -Times 1 -Exactly
            $script:dialogSummary | Should -Match '2 warning'
            $script:dialogSummary | Should -Match 'preview-w'
        }
    }

    It 'never shows the confirmation dialog when the preview errored' {
        InModuleScope woscap {
            $script:previewError = 'pack broke'
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            Should -Not -Invoke Show-WoscapGuiRemediationDialog
            Should -Invoke Invoke-WoscapGuiScan -Times 1 -Exactly -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            $script:shown | Should -Contain 'Remediation failed: pack broke'
            $script:form.Tag['Run'].Enabled | Should -BeTrue
        }
    }

    It 'keeps preview warnings visible after the apply completes' {
        InModuleScope woscap {
            $script:previewWarning = 'preview-w'
            $script:applyOutcome = 'Warning'
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:form.Tag['Status'].Text | Should -Match 'Preview: 2 warning'
            $tip = $script:form.Tag['StatusTip'].GetToolTip($script:form.Tag['Status'])
            $tip | Should -Match 'preview-w'
            $tip | Should -Match 'apply-w'
        }
    }

    It 're-scans with the Benchmark and ContentPath the remediated results came from' {
        InModuleScope woscap {
            $script:form.Tag['ResultsContext'] = @{ Benchmark = 'Edge'; ContentPath = $TestDrive }
            Mock Show-WoscapGuiRemediationDialog {
                $script:form.Tag['Benchmark'].SelectedItem = 'Windows11'
                $script:form.Tag['ContentPath'].Text = ''
                @('R-1')
            }
            Mock Show-WoscapGuiRemediationReport { 'Rescan' }
            $script:rescanWith = $null
            Mock Invoke-WoscapGuiRun { $script:rescanWith = @{ B = [string]$Tag['Benchmark'].SelectedItem; C = [string]$Tag['ContentPath'].Text }; $true }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:rescanWith.B | Should -Be 'Edge'
            $script:rescanWith.C | Should -Be $TestDrive
        }
    }

    It 'keeps Remediate disabled after a fix was applied, until a new scan completes' {
        InModuleScope woscap {
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:form.Tag['Run'].Enabled           | Should -BeTrue
            $script:form.Tag['Remediate'].Enabled     | Should -BeFalse
            $script:form.Tag['MenuRemediate'].Enabled | Should -BeFalse
            $script:form.Tag['Xccdf'].Text = (Get-Module woscap).Path
            Mock Invoke-WoscapGuiScan { throw 'no runspace' } -ParameterFilter { $Command -ne 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRun -Tag $script:form.Tag
            $script:form.Tag['Remediate'].Enabled | Should -BeFalse -Because 'a scan that never started leaves the grid stale'
            Mock Invoke-WoscapGuiScan {
                & $OnComplete -Results @([pscustomobject]@{ Host = $env:COMPUTERNAME; StigId = 'R-1'; Severity = 'high'; Status = 'NotAFinding'; Title = 'r1'; Exception = $null })
            } -ParameterFilter { $Command -ne 'Invoke-WoscapRemediation' }
            Invoke-WoscapGuiRun -Tag $script:form.Tag
            $script:form.Tag['Remediate'].Enabled     | Should -BeTrue
            $script:form.Tag['MenuRemediate'].Enabled | Should -BeTrue
        }
    }

    It 're-enables Remediate when no fix reached State Applied' {
        InModuleScope woscap {
            $script:applyResults = $script:failed
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            $script:form.Tag['Remediate'].Enabled | Should -BeTrue
        }
    }

    It 'reports automatic rows the operator unticked as Skipped / Not selected' {
        InModuleScope woscap {
            $script:plan = @(
                $script:plan[0]
                [pscustomobject]@{ StigId = 'R-2'; StigIds = @('R-2'); Title = 'r2'; Action = 'a2'; State = 'Planned'; Detail = '' }
                $script:plan[1]
            )
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:reported | ForEach-Object StigId) | Should -Be @('R-1', 'R-2', 'M-1')
            $skipped = @($script:reported | Where-Object StigId -eq 'R-2')[0]
            $skipped.State  | Should -Be 'Skipped'
            $skipped.Detail | Should -Be 'Not selected'
            $report = New-WoscapGuiRemediationReport -Result @($script:reported)
            try { $report.Tag['Summary'].Text | Should -Match 'Skipped: 1' } finally { $report.Dispose() }
        }
    }

    It 'includes the preview Manual items in the post-apply report' {
        InModuleScope woscap {
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:reported | ForEach-Object StigId) | Should -Be @('R-1', 'M-1')
            $report = New-WoscapGuiRemediationReport -Result @($script:reported)
            try { $report.Tag['Summary'].Text | Should -Match 'Manual: 1' } finally { $report.Dispose() }
        }
    }
}

# Spec 7.6 (#36): a multi-write fix is one dialog row, and unticking it skips all of its writes.
Describe 'Invoke-WoscapGuiRemediate with a multi-write fix' -Skip:(-not $script:IsSta) {
    BeforeEach {
        InModuleScope woscap {
            $me = $env:COMPUTERNAME
            $script:form = New-WoscapMainForm
            foreach ($id in 'C-1', 'R-1') {
                $script:form.Tag['Results'].Add([pscustomobject]@{ Host = $me; StigId = $id; Severity = 'high'; Status = 'Open'; Title = $id; Exception = $null })
            }
            $script:form.Tag['ResultsContext'] = @{ Benchmark = 'Windows11'; ContentPath = 'TestDrive:\pack' }
            Update-WoscapGuiView -Tag $script:form.Tag
            Mock Show-WoscapGuiMessage { }
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Test-WoscapGuiElevated { $true }
            Mock Show-WoscapGuiRemediationReport { 'Close' }
            Mock Import-ContentPack { @{
                'C-1' = @{ Type = 'All'; Checks = @(
                    @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\A'; Name = 'One'; Operator = 'eq'; Expected = 1 }
                    @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\B'; Name = 'Two'; Operator = 'eq'; Expected = 2 }
                )}
                'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\S'; Name = 'N'; Operator = 'eq'; Expected = 1 }
            } }
            Mock Test-Path { $true }
            Mock New-Item {}
            Mock Set-ItemProperty {}
            Mock Set-WoscapRegValue {}
            Mock Test-Descriptor { [pscustomobject]@{ Result = 'Pass'; Observed = 1; Expected = 1 } }
            # Run the real remediation in-process (every write above is mocked) instead of a runspace.
            Mock Invoke-WoscapGuiScan {
                $r = @(Invoke-WoscapRemediation @ScanParameters)
                if ($OnSettled) { & $OnSettled -Results $r -Outcome ([pscustomobject]@{ Kind = 'None'; Message = ''; Count = 0 }) }
                else { & $OnComplete -Results $r }
            } -ParameterFilter { $Command -eq 'Invoke-WoscapRemediation' }
            $script:rows = $null
        }
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'shows one row listing both writes, and unticking it writes neither' {
        InModuleScope woscap {
            Mock Show-WoscapGuiRemediationDialog {
                $d = New-WoscapGuiRemediationDialog -Plan $Plan -Summary $Summary -Elevated $Elevated
                try {
                    $script:rows = @($d.Tag['Grid'].Rows | ForEach-Object { "$(@($_.Tag.StigIds) -join ',')|$($_.Cells[3].Value)" })
                    foreach ($row in $d.Tag['Grid'].Rows) { if (@($row.Tag.StigIds) -contains 'C-1') { $row.Cells[0].Value = $false } }
                    Get-WoscapGuiRemediationSelection -Tag $d.Tag
                } finally { $d.Dispose() }
            }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:rows | Sort-Object) | Should -Be @(
                'C-1|Set HKLM:\SOFTWARE\A\One = 1 (dword); Set HKLM:\SOFTWARE\B\Two = 2 (dword)'
                'R-1|Set HKLM:\SOFTWARE\S\N = 1 (dword)')
            Should -Invoke Set-WoscapRegValue -Exactly 1
            Should -Invoke Set-WoscapRegValue -Exactly 1 -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\S' }
        }
    }

    It 'applies both writes when the row stays ticked' {
        InModuleScope woscap {
            Mock Show-WoscapGuiRemediationDialog {
                $d = New-WoscapGuiRemediationDialog -Plan $Plan -Summary $Summary -Elevated $Elevated
                try { Get-WoscapGuiRemediationSelection -Tag $d.Tag } finally { $d.Dispose() }
            }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            Should -Invoke Set-WoscapRegValue -Exactly 3
            Should -Invoke Set-WoscapRegValue -Exactly 1 -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\A' }
            Should -Invoke Set-WoscapRegValue -Exactly 1 -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\B' }
        }
    }

    It 'marks the grid stale and reports PartiallyApplied when a later write fails' {
        InModuleScope woscap {
            Mock Set-WoscapRegValue { if ($Path -eq 'HKLM:\SOFTWARE\B') { throw 'access denied' } }
            Mock Show-WoscapGuiRemediationDialog { @('C-1') }
            Mock Show-WoscapGuiRemediationReport { $script:reportRows = @($Result); 'Close' }
            Invoke-WoscapGuiRemediate -Tag $script:form.Tag
            @($script:reportRows | Where-Object StigId -eq 'C-1').State | Should -Be 'PartiallyApplied'
            $script:form.Tag['ResultsStale'] | Should -BeTrue -Because 'a partial fix changed the host'
        }
    }
}

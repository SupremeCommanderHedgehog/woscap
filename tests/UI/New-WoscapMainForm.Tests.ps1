BeforeDiscovery {
    # WinForms control construction requires an STA apartment. CI (Windows PowerShell
    # 5.1 console) is STA; guard so these tests SKIP (never fail) on an MTA host.
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms
    # A real, existing file to satisfy the Run handler's XCCDF existence check.
    $script:ExistingFile = (Get-Module woscap).Path   # woscap.psd1 full path
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'New-WoscapMainForm' -Skip:(-not $script:IsSta) {

    It 'returns a Form carrying its key controls in Tag' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $form | Should -BeOfType [System.Windows.Forms.Form]
                $tag = $form.Tag
                foreach ($key in 'Benchmark','Xccdf','Targets','Profile','UseCred','Run',
                                 'Progress','Status','Grid','FilterSeverity','FilterStatus',
                                 'Find','Format','Export','Results') {
                    $tag.ContainsKey($key) | Should -BeTrue -Because "Tag should expose '$key'"
                }
            } finally { $form.Dispose() }
        }
    }

    It 'populates the benchmark dropdown from the Content directory and defaults to Windows11' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                @($form.Tag['Benchmark'].Items) | Should -Contain 'Windows11'
                @($form.Tag['Benchmark'].Items) | Should -Contain 'Edge'
                # Default must be Windows11 even though Chrome/Edge sort ahead of it alphabetically.
                $form.Tag['Benchmark'].SelectedItem | Should -Be 'Windows11'
            } finally { $form.Dispose() }
        }
    }

    It 'derives the severity/status/format dropdowns from the canonical vocabularies' {
        InModuleScope woscap {
            $vocab = Get-WoscapGuiVocabulary
            $form = New-WoscapMainForm
            try {
                # 'All' is a GUI-only filter prefix; the rest must match the canonical lists.
                @($form.Tag['FilterSeverity'].Items) | Should -Be (@('All') + $vocab.Severity)
                @($form.Tag['FilterStatus'].Items)   | Should -Be (@('All') + $vocab.Status)
                @($form.Tag['Format'].Items)         | Should -Be $vocab.Format
            } finally { $form.Dispose() }
        }
    }

    It 'populates the grid and enables Export when a scan completes' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan {
                $canned = @(
                    [pscustomobject]@{ Host='H1'; StigId='V-1'; Severity='high';   Status='Open';        Title='T1'; Exception=$null }
                    [pscustomobject]@{ Host='H1'; StigId='V-2'; Severity='medium'; Status='NotAFinding'; Title='T2'; Exception=$null }
                )
                & $OnComplete -Results $canned
            }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                Invoke-WoscapGuiRun -Tag $form.Tag
                Should -Invoke Invoke-WoscapGuiScan -Times 1 -Scope It
                $form.Tag['Grid'].Rows.Count | Should -Be 2
                $form.Tag['Export'].Enabled   | Should -BeTrue
                @($form.Tag['Results']).Count | Should -Be 2
            } finally { $form.Dispose() }
        }
    }

    It 'builds the scan splat from the input controls' {
        InModuleScope woscap {
            $captured = $null
            Mock Invoke-WoscapGuiScan { $script:captured = $ScanParameters; & $OnComplete -Results @() }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text   = (Get-Module woscap).Path
                $form.Tag['Targets'].Text = 'SRV01, SRV02'
                # Do NOT touch the dropdown: the splat must carry the DEFAULT benchmark. With Edge and
                # Chrome packs present it must still default to Windows11, not the alphabetically-first
                # pack (that would silently scan a Windows XCCDF against an app pack).
                Invoke-WoscapGuiRun -Tag $form.Tag
                $script:captured['Benchmark']    | Should -Be 'Windows11'
                $script:captured['ComputerName'] | Should -Be @('SRV01','SRV02')
            } finally { $form.Dispose() }
        }
    }

    It 'shows a validation message and does not scan when XCCDF path is missing' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan { }
            Mock Show-WoscapGuiMessage { }   # message seam (see impl)
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = 'C:\does\not\exist.xml'
                Invoke-WoscapGuiRun -Tag $form.Tag
                Should -Not -Invoke Invoke-WoscapGuiScan -Scope It
                Should -Invoke Show-WoscapGuiMessage -Times 1 -Scope It
            } finally { $form.Dispose() }
        }
    }

    It 'requests a credential when Use alternate credential is checked' {
        InModuleScope woscap {
            $captured = $null
            Mock Invoke-WoscapGuiScan { $script:captured = $ScanParameters; & $OnComplete -Results @() }
            Mock Get-WoscapGuiCredential { [pscredential]::new('u', (ConvertTo-SecureString 'p' -AsPlainText -Force)) }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                $form.Tag['UseCred'].Checked = $true
                Invoke-WoscapGuiRun -Tag $form.Tag
                Should -Invoke Get-WoscapGuiCredential -Times 1 -Scope It
                $script:captured.ContainsKey('Credential') | Should -BeTrue
            } finally { $form.Dispose() }
        }
    }

    It 'applies the severity filter to the grid' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan {
                & $OnComplete -Results @(
                    [pscustomobject]@{ Host='H1'; StigId='V-1'; Severity='high';   Status='Open';        Title='T1'; Exception=$null }
                    [pscustomobject]@{ Host='H1'; StigId='V-2'; Severity='medium'; Status='NotAFinding'; Title='T2'; Exception=$null }
                )
            }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                Invoke-WoscapGuiRun -Tag $form.Tag
                $form.Tag['Grid'].Rows.Count | Should -Be 2
                $form.Tag['FilterSeverity'].SelectedItem = 'high'   # raises SelectedIndexChanged
                $form.Tag['Grid'].Rows.Count | Should -Be 1
            } finally { $form.Dispose() }
        }
    }

    It 'exports the full result set via Export-WoscapResult' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan {
                & $OnComplete -Results @([pscustomobject]@{ Host='H1'; StigId='V-1'; Severity='high'; Status='Open'; Title='T1'; Exception=$null })
            }
            Mock Export-WoscapResult { }
            Mock Get-WoscapGuiSavePath { 'C:\out\report.cklb' }   # SaveFileDialog seam
            Mock Show-WoscapGuiMessage { }                        # never pop a real MessageBox
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                Invoke-WoscapGuiRun -Tag $form.Tag
                $form.Tag['Format'].SelectedItem = 'cklb'
                Invoke-WoscapGuiExport -Tag $form.Tag
                Should -Invoke Export-WoscapResult -Times 1 -Scope It -ParameterFilter {
                    $Format -eq 'cklb' -and $Path -eq 'C:\out\report.cklb' -and @($Result).Count -eq 1
                }
            } finally { $form.Dispose() }
        }
    }

    It 'shows a message and does not scan when no benchmark is selected' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan { }
            Mock Show-WoscapGuiMessage { }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                $form.Tag['Benchmark'].Items.Clear()   # simulate a missing/empty Content/ dir
                Invoke-WoscapGuiRun -Tag $form.Tag
                Should -Not -Invoke Invoke-WoscapGuiScan -Scope It
                Should -Invoke Show-WoscapGuiMessage -Times 1 -Scope It
            } finally { $form.Dispose() }
        }
    }

    It 'anchors the grid to all four edges and pins the export row to the bottom so the table resizes with the window' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $A = [System.Windows.Forms.AnchorStyles]
                $form.Tag['Grid'].Anchor   | Should -Be ($A::Top -bor $A::Bottom -bor $A::Left -bor $A::Right)
                $form.Tag['Export'].Anchor | Should -Be ($A::Bottom -bor $A::Left)
                # A minimum size keeps the layout from collapsing onto itself.
                $form.MinimumSize.Width  | Should -BeGreaterThan 0
                $form.MinimumSize.Height | Should -BeGreaterThan 0
            } finally { $form.Dispose() }
        }
    }

    It 'reports a partial scan (results + errors) as a non-modal warning, not a failure' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan {
                & $OnComplete -Results @([pscustomobject]@{ Host='H1'; StigId='V-1'; Severity='high'; Status='Open'; Title='T1'; Exception=$null })
                & $OnWarning -Message 'SRV03 unreachable' -Count 1
            }
            Mock Show-WoscapGuiMessage { }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                Invoke-WoscapGuiRun -Tag $form.Tag
                $form.Tag['Grid'].Rows.Count | Should -Be 1
                $form.Tag['Export'].Enabled  | Should -BeTrue
                $form.Tag['Status'].Text     | Should -Be 'Done (1 warning).'
                # The warning detail is preserved non-modally (tooltip), NOT a dialog.
                $form.Tag['StatusTip'].GetToolTip($form.Tag['Status']) | Should -Match 'SRV03 unreachable'
                Should -Not -Invoke Show-WoscapGuiMessage -Scope It
                $form.Tag['Run'].Enabled | Should -BeTrue
            } finally { $form.Dispose() }
        }
    }

    It 'pluralizes the warning count' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan {
                & $OnComplete -Results @([pscustomobject]@{ Host='H1'; StigId='V-1'; Severity='high'; Status='Open'; Title='T1'; Exception=$null })
                & $OnWarning -Message "a`nb" -Count 2
            }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                Invoke-WoscapGuiRun -Tag $form.Tag
                $form.Tag['Status'].Text | Should -Be 'Done (2 warnings).'
            } finally { $form.Dispose() }
        }
    }

    It 'still shows a modal and sets Failed. on a hard error (no results)' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan {
                & $OnComplete -Results @()
                & $OnError -Message 'everything failed'
            }
            Mock Show-WoscapGuiMessage { }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                Invoke-WoscapGuiRun -Tag $form.Tag
                $form.Tag['Status'].Text | Should -Be 'Failed.'
                Should -Invoke Show-WoscapGuiMessage -Times 1 -Scope It
            } finally { $form.Dispose() }
        }
    }

    It 'clears the stale grid and resets the progress bar when a later scan hard-fails' {
        InModuleScope woscap {
            $script:runCount = 0
            Mock Invoke-WoscapGuiScan {
                $script:runCount++
                if ($script:runCount -eq 1) {
                    & $OnComplete -Results @(
                        [pscustomobject]@{ Host='H1'; StigId='V-1'; Severity='high';   Status='Open';        Title='T1'; Exception=$null }
                        [pscustomobject]@{ Host='H1'; StigId='V-2'; Severity='medium'; Status='NotAFinding'; Title='T2'; Exception=$null }
                    )
                } else {
                    # Terminating path: only OnError fires (OnComplete is skipped).
                    & $OnError -Message 'boom'
                }
            }
            Mock Show-WoscapGuiMessage { }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                Invoke-WoscapGuiRun -Tag $form.Tag        # populate
                $form.Tag['Grid'].Rows.Count | Should -Be 2
                Invoke-WoscapGuiRun -Tag $form.Tag        # hard-fail
                $form.Tag['Grid'].Rows.Count | Should -Be 0 -Because 'a failed scan must not leave stale rows'
                $form.Tag['Export'].Enabled  | Should -BeFalse
                $form.Tag['Progress'].Value  | Should -Be 0
                $form.Tag['Status'].Text     | Should -Be 'Failed.'
            } finally { $form.Dispose() }
        }
    }

    It 'clears a stale warning tooltip on a subsequent clean scan' {
        InModuleScope woscap {
            $script:runCount = 0
            Mock Invoke-WoscapGuiScan {
                $script:runCount++
                $row = @([pscustomobject]@{ Host='H1'; StigId='V-1'; Severity='high'; Status='Open'; Title='T1'; Exception=$null })
                & $OnComplete -Results $row
                if ($script:runCount -eq 1) { & $OnWarning -Message 'SRV03 unreachable' -Count 1 }
            }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                Invoke-WoscapGuiRun -Tag $form.Tag        # scan 1: warning sets tooltip
                $form.Tag['StatusTip'].GetToolTip($form.Tag['Status']) | Should -Match 'SRV03'
                Invoke-WoscapGuiRun -Tag $form.Tag        # scan 2: clean
                $form.Tag['StatusTip'].GetToolTip($form.Tag['Status']) | Should -BeNullOrEmpty
                $form.Tag['Status'].Text | Should -Be 'Done.'
            } finally { $form.Dispose() }
        }
    }

    It 're-enables Run and reports an error when the scan fails to start' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan { throw 'boom' }
            Mock Show-WoscapGuiMessage { }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                Invoke-WoscapGuiRun -Tag $form.Tag
                Should -Invoke Show-WoscapGuiMessage -Times 1 -Scope It
                $form.Tag['Run'].Enabled | Should -BeTrue
            } finally { $form.Dispose() }
        }
    }
}

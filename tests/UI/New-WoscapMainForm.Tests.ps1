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
                foreach ($key in 'Benchmark','Xccdf','Targets','Profiles','ProfileAdd','ProfileRemove',
                                 'ProfileUp','ProfileDown','UseCred','Run','AdvancedToggle','AdvancedGroup',
                                 'ContentPath','ContentPathDefault','ThrottleLimit','JsonPath',
                                 'Progress','Status','Grid','FilterSeverity','FilterStatus',
                                 'Find','Format','Export','Results','Menu','MenuRun','MenuExport','Remediate','MenuRemediate',
                                 'Tabs','ScanTab','ContentTab','IntegrationsTab') {
                    $tag.ContainsKey($key) | Should -BeTrue -Because "Tag should expose '$key'"
                }
                $tag.ContainsKey('Profile') | Should -BeFalse -Because 'the single Profile box was replaced by the Profiles list'
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

    It 'docks menu top and tabs fill, and the grid fills its row so the table resizes with the window' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $D = [System.Windows.Forms.DockStyle]
                $form.Tag['Menu'].Dock  | Should -Be $D::Top
                $form.Tag['Tabs'].Dock  | Should -Be $D::Fill
                $form.Tag['Grid'].Dock  | Should -Be $D::Fill
                $form.MainMenuStrip     | Should -Be $form.Tag['Menu']
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

    It 'has Scan, Content and Integrations tabs, none of them a placeholder' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                @($form.Tag['Tabs'].TabPages | ForEach-Object Text) | Should -Be @('Scan', 'Content', 'Integrations')
                $form.Tag['ContentTab'].Controls[0].Text      | Should -Not -Match '#17'
                $form.Tag['IntegrationsTab'].Controls[0].Text | Should -Not -Match '#18'
            } finally { $form.Dispose() }
        }
    }

    It 'builds File/Scan/Content/Integrations/Help menus with Run=F5 and Export=Ctrl+E' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $K = [System.Windows.Forms.Keys]
                @($form.Tag['Menu'].Items | ForEach-Object Text) | Should -Be @('&File', '&Scan', '&Content', '&Integrations', '&Help')
                $form.Tag['MenuRun'].ShortcutKeys    | Should -Be $K::F5
                $form.Tag['MenuExport'].ShortcutKeys | Should -Be ($K::Control -bor $K::E)
            } finally { $form.Dispose() }
        }
    }

    It 'has Scan > Remediate... and starts with Remediate disabled on button and menu' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $scanMenu = @($form.Tag['Menu'].Items | Where-Object { $_.Text -eq '&Scan' })[0]
                @($scanMenu.DropDownItems | ForEach-Object Text) | Should -Contain '&Remediate...'
                $form.Tag['Remediate'].Enabled     | Should -BeFalse
                $form.Tag['MenuRemediate'].Enabled | Should -BeFalse
            } finally { $form.Dispose() }
        }
    }

    It 'enables Remediate after a scan with results and disables it while a scan runs' {
        InModuleScope woscap {
            $script:phase = 'complete'
            Mock Invoke-WoscapGuiScan {
                if ($script:phase -eq 'complete') {
                    & $OnComplete -Results @([pscustomobject]@{ Host='H1'; StigId='V-1'; Severity='high'; Status='Open'; Title='T1'; Exception=$null })
                }
            }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                Invoke-WoscapGuiRun -Tag $form.Tag
                $form.Tag['Remediate'].Enabled     | Should -BeTrue
                $form.Tag['MenuRemediate'].Enabled | Should -BeTrue
                $script:phase = 'inflight'
                Invoke-WoscapGuiRun -Tag $form.Tag
                $form.Tag['Remediate'].Enabled     | Should -BeFalse
                $form.Tag['MenuRemediate'].Enabled | Should -BeFalse
            } finally { $form.Dispose() }
        }
    }

    It 'disables Remediate after a hard scan failure' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan { & $OnError -Message 'boom' }
            Mock Show-WoscapGuiMessage { }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                Invoke-WoscapGuiRun -Tag $form.Tag
                $form.Tag['Remediate'].Enabled | Should -BeFalse
            } finally { $form.Dispose() }
        }
    }

    It 'starts with Export disabled on both button and menu, and Advanced collapsed' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $form.Tag['Export'].Enabled     | Should -BeFalse
                $form.Tag['MenuExport'].Enabled | Should -BeFalse
                $form.Tag['AdvancedExpanded']   | Should -BeFalse
                $form.Tag['AdvancedToggle'].Text | Should -Be '[+] Advanced'
            } finally { $form.Dispose() }
        }
    }

    It 'initializes throttle from the cmdlet default and shows the default content path' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $form.Tag['ThrottleLimit'].Value | Should -Be (Get-WoscapGuiScanDefault).ThrottleLimit
                $form.Tag['ContentPathDefault'].Text | Should -Match 'Content\\Windows11$'
            } finally { $form.Dispose() }
        }
    }

    It 'mirrors Export enabled-state onto the menu after a scan with results' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan {
                & $OnComplete -Results @([pscustomobject]@{ Host='H1'; StigId='V-1'; Severity='high'; Status='Open'; Title='T1'; Exception=$null })
            }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                Invoke-WoscapGuiRun -Tag $form.Tag
                $form.Tag['MenuExport'].Enabled | Should -BeTrue
                $form.Tag['MenuRun'].Enabled    | Should -BeTrue
            } finally { $form.Dispose() }
        }
    }

    It 'menu Run triggers a scan' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan { & $OnComplete -Results @() }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                $form.Tag['MenuRun'].PerformClick()
                Should -Invoke Invoke-WoscapGuiScan -Times 1 -Exactly -Scope It
            } finally { $form.Dispose() }
        }
    }

    It 'keeps every visible Scan-tab control inside its parent at default and minimum size, Advanced collapsed and expanded' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $form.Show(); [System.Windows.Forms.Application]::DoEvents()
                $walk = { param($c) foreach ($child in $c.Controls) { $child; & $walk $child } }
                $bad = [System.Collections.Generic.List[string]]::new()
                foreach ($size in $form.Size, $form.MinimumSize) {
                    foreach ($expanded in $false, $true) {
                        $form.Size = $size
                        Set-WoscapGuiAdvanced -Tag $form.Tag -Expanded $expanded
                        [System.Windows.Forms.Application]::DoEvents()
                        foreach ($c in @(& $walk $form.Tag['ScanTab'])) {
                            if (-not $c.Visible) { continue }
                            $w = $c.Parent.ClientSize.Width
                            if ($c.Left -lt 0 -or $c.Right -gt $w) {
                                $bad.Add(('{0} "{1}" L={2} R={3} parentW={4} at {5}x{6} expanded={7}' -f
                                    $c.GetType().Name, $c.Text, $c.Left, $c.Right, $w, $size.Width, $size.Height, $expanded))
                            }
                        }
                    }
                }
                $bad | Should -BeNullOrEmpty -Because 'no Scan-tab control may overflow its parent'
            } finally { $form.Close(); $form.Dispose() }
        }
    }

    It 'keeps right-anchored controls at a constant gap from the right edge when resized' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $form.Show(); [System.Windows.Forms.Application]::DoEvents()
                Set-WoscapGuiAdvanced -Tag $form.Tag -Expanded $true
                [System.Windows.Forms.Application]::DoEvents()
                $walk = { param($c) foreach ($child in $c.Controls) { $child; & $walk $child } }
                $A = [System.Windows.Forms.AnchorStyles]
                $right = @(& $walk $form.Tag['ScanTab'] | Where-Object {
                    ($_.Anchor -band $A::Right) -and -not ($_.Anchor -band $A::Left)
                })
                $right.Count | Should -BeGreaterThan 0
                $gap = { param($c) $c.Parent.ClientSize.Width - $c.Right }
                $baseline = @{}
                foreach ($c in $right) { $baseline[$c] = & $gap $c }
                foreach ($size in $form.MinimumSize, (New-Object System.Drawing.Size(1200, 800))) {
                    $form.Size = $size
                    [System.Windows.Forms.Application]::DoEvents()
                    foreach ($c in $right) {
                        & $gap $c | Should -Be $baseline[$c] -Because ('{0} "{1}" gap at {2}x{3}' -f $c.GetType().Name, $c.Text, $size.Width, $size.Height)
                    }
                }
            } finally { $form.Close(); $form.Dispose() }
        }
    }

    It 'menu Run is disabled while a scan is in flight' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan { }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                Invoke-WoscapGuiRun -Tag $form.Tag
                $form.Tag['Run'].Enabled     | Should -BeFalse
                $form.Tag['MenuRun'].Enabled | Should -BeFalse
            } finally { $form.Dispose() }
        }
    }

    It 'Profile Add uses the open-file seam and appends the chosen files' {
        InModuleScope woscap {
            Mock Get-WoscapGuiOpenPath { @('C:\p1.psd1', 'C:\p2.psd1') }
            $form = New-WoscapMainForm
            try {
                Invoke-WoscapGuiProfileAdd -Tag $form.Tag
                @($form.Tag['Profiles'].Items) | Should -Be @('C:\p1.psd1', 'C:\p2.psd1')
                Should -Invoke Get-WoscapGuiOpenPath -Times 1 -Exactly -ParameterFilter { $Multiselect }
            } finally { $form.Dispose() }
        }
    }

    It 'passes profiles in list order and the Advanced options into the scan splat' {
        InModuleScope woscap {
            $script:captured = $null
            Mock Invoke-WoscapGuiScan { $script:captured = $ScanParameters; & $OnComplete -Results @() }
            $existing = (Get-Module woscap).Path
            $dir = Split-Path $existing -Parent
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = $existing
                Add-WoscapGuiProfile -Tag $form.Tag -Path @($existing, (Join-Path $dir 'woscap.psd1'))
                $form.Tag['ContentPath'].Text = $dir
                $form.Tag['ThrottleLimit'].Value = 3
                $form.Tag['JsonPath'].Text = Join-Path $dir 'out.json'
                Invoke-WoscapGuiRun -Tag $form.Tag
                @($script:captured['ProfilePath']) | Should -Be @($existing, (Join-Path $dir 'woscap.psd1'))
                $script:captured['ContentPath']   | Should -Be $dir
                $script:captured['ThrottleLimit'] | Should -Be 3
                $script:captured['JsonPath']      | Should -Be (Join-Path $dir 'out.json')
            } finally { $form.Dispose() }
        }
    }

    It 'omits ThrottleLimit when left at the default' {
        InModuleScope woscap {
            $script:captured = $null
            Mock Invoke-WoscapGuiScan { $script:captured = $ScanParameters; & $OnComplete -Results @() }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                Invoke-WoscapGuiRun -Tag $form.Tag
                $script:captured.ContainsKey('ThrottleLimit') | Should -BeFalse
            } finally { $form.Dispose() }
        }
    }

    It 'refuses to scan when <Case>' -ForEach @(
        @{ Case = 'the content path does not exist'; Field = 'ContentPath'; Value = 'C:\does\not\exist\pack'; Match = 'Content path' }
        @{ Case = 'a profile file does not exist';   Field = 'Profiles';    Value = 'C:\does\not\exist\p.psd1'; Match = 'p\.psd1' }
        @{ Case = 'the JSON output folder does not exist'; Field = 'JsonPath'; Value = 'C:\does\not\exist\out.json'; Match = 'JSON' }
    ) {
        InModuleScope woscap -Parameters @{ Field = $Field; Value = $Value; Match = $Match } {
            param($Field, $Value, $Match)
            Mock Invoke-WoscapGuiScan { }
            $script:shown = @()
            Mock Show-WoscapGuiMessage { $script:shown += $Text }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                if ($Field -eq 'Profiles') { Add-WoscapGuiProfile -Tag $form.Tag -Path @($Value) }
                else { $form.Tag[$Field].Text = $Value }
                Invoke-WoscapGuiRun -Tag $form.Tag
                Should -Not -Invoke Invoke-WoscapGuiScan -Scope It
                @($script:shown).Count | Should -Be 1
                $script:shown[0] | Should -Match $Match
                $form.Tag['Run'].Enabled | Should -BeTrue
            } finally { $form.Dispose() }
        }
    }

    It 'validates paths before prompting for a credential' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan { }
            Mock Show-WoscapGuiMessage { }
            Mock Get-WoscapGuiCredential { [pscredential]::new('u', (ConvertTo-SecureString 'p' -AsPlainText -Force)) }
            $form = New-WoscapMainForm
            try {
                $form.Tag['Xccdf'].Text = (Get-Module woscap).Path
                $form.Tag['UseCred'].Checked = $true
                $form.Tag['ContentPath'].Text = 'C:\does\not\exist\pack'
                Invoke-WoscapGuiRun -Tag $form.Tag
                Should -Not -Invoke Get-WoscapGuiCredential -Scope It
                Should -Not -Invoke Invoke-WoscapGuiScan -Scope It
            } finally { $form.Dispose() }
        }
    }
}

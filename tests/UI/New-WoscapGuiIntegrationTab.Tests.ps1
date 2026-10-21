BeforeDiscovery {
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
    # Expected enablement per bundled plugin: capability hook -> action.
    $script:BundledCases = @(
        @{ Plugin = 'Ansible'; Enabled = @('IntegrationImportTargets', 'IntegrationExportFindings', 'IntegrationExportRemediation') }
        @{ Plugin = 'OpenVAS'; Enabled = @('IntegrationImportFindings', 'IntegrationRunScan') }
        @{ Plugin = 'Zabbix';  Enabled = @('IntegrationImportTargets', 'IntegrationExportFindings') }
    )
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms

    $script:Actions = @('IntegrationImportTargets', 'IntegrationImportFindings', 'IntegrationRunScan',
        'IntegrationExportFindings', 'IntegrationExportRemediation')

    # A plugin folder with one good plugin and one whose implementation is missing.
    function New-TestPluginRoot([string] $Root) {
        $good = Join-Path $Root 'Good'
        $bad = Join-Path $Root 'Broken'
        New-Item -ItemType Directory -Path $good, $bad -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $good 'plugin.psd1') -Value "@{ Name = 'Good'; Version = '2.0.0'; Capabilities = @('Get-Targets'); Implementation = 'implementation.ps1' }"
        Set-Content -LiteralPath (Join-Path $good 'implementation.ps1') -Value "@{ 'Get-Targets' = { param(`$Source, `$Config) 'h1' } }"
        Set-Content -LiteralPath (Join-Path $bad 'plugin.psd1') -Value "@{ Name = 'Broken'; Version = '1.0.0'; Capabilities = @('Get-Targets', 'Export-Findings'); Implementation = 'missing.ps1' }"
        $Root
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Integrations tab' -Skip:(-not $script:IsSta) {
    BeforeEach {
        # No real modal, no network, no real file/folder dialog.
        Mock -ModuleName woscap Show-WoscapGuiMessage { }
        Mock -ModuleName woscap Get-WoscapGuiCredential { }
        Mock -ModuleName woscap Get-WoscapGuiFolderPath { $null }
        Mock -ModuleName woscap Get-WoscapGuiOpenPath { @() }
        Mock -ModuleName woscap Get-WoscapGuiSavePath { $null }
        Mock -ModuleName woscap Show-WoscapGuiConfigForm { $null }
        Mock -ModuleName woscap Show-WoscapGuiDownloadDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiUpdateDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiRemoveDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiDisaTermsDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiRemediationDialog { $null }
        Mock -ModuleName woscap Invoke-WoscapGuiScan { throw 'the runner must not start in a tab test' }
        Mock -ModuleName woscap Import-WoscapIntegration { throw 'no integration cmdlet in a tab test' }
        Mock -ModuleName woscap Invoke-WoscapIntegration { throw 'no integration cmdlet in a tab test' }
        Mock -ModuleName woscap Export-WoscapIntegration { throw 'no integration cmdlet in a tab test' }
        # The Content tab must never list the real cache from these tests.
        Mock -ModuleName woscap Get-WoscapBenchmark { }
        InModuleScope woscap {
            function script:Invoke-WoscapTestClick([System.Windows.Forms.Button] $Button) {
                $m = [System.Windows.Forms.Button].GetMethod('OnClick', [System.Reflection.BindingFlags]'Instance, NonPublic')
                [void]$m.Invoke($Button, @([System.EventArgs]::Empty))
            }
            function script:Select-TestPlugin([hashtable] $T, [string] $Name) {
                $g = $T['IntegrationGrid']
                $g.ClearSelection()
                $row = @($g.Rows | Where-Object { $_.Tag.Name -eq $Name })[0]
                $row.Selected = $true
                Update-WoscapGuiIntegrationSelection -Tag $T
                $row
            }
        }
        $script:PluginRoot = New-TestPluginRoot (Join-Path $TestDrive ('plugins-' + [guid]::NewGuid().ToString('N')))
    }

    It 'exposes every Integration Tag key, including the menu twins' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                foreach ($key in 'IntegrationPath', 'IntegrationPathBrowse', 'IntegrationPathDefault', 'IntegrationGrid',
                                 'IntegrationImportTargets', 'IntegrationImportFindings', 'IntegrationRunScan',
                                 'IntegrationExportFindings', 'IntegrationExportRemediation', 'IntegrationRefresh',
                                 'IntegrationStatus', 'MenuIntegrationImportTargets', 'MenuIntegrationImportFindings',
                                 'MenuIntegrationRunScan', 'MenuIntegrationExportFindings',
                                 'MenuIntegrationExportRemediation', 'MenuIntegrationRefresh') {
                    $form.Tag.ContainsKey($key) | Should -BeTrue -Because "Tag should expose '$key'"
                    $form.Tag[$key] | Should -Not -BeNullOrEmpty -Because "'$key' must be a control"
                }
            } finally { $form.Dispose() }
        }
    }

    It 'replaces the #18 placeholder with real controls' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $walk = { param($c) foreach ($child in $c.Controls) { $child; & $walk $child } }
                @(& $walk $form.Tag['IntegrationsTab'] | Where-Object { $_.Text -match 'coming in #18' }) | Should -BeNullOrEmpty
                $form.Tag['IntegrationGrid'].FindForm() | Should -Be $form
                @($form.Tag['IntegrationGrid'].Columns | ForEach-Object HeaderText) | Should -Be @('Name', 'Version', 'Conformant', 'Capabilities')
            } finally { $form.Dispose() }
        }
    }

    It 'has Integrations menu items for every action, Refresh and Open Integrations tab' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $menu = @($form.Tag['Menu'].Items | Where-Object { $_.Text -eq '&Integrations' })[0]
                $texts = @($menu.DropDownItems | Where-Object { $_ -is [System.Windows.Forms.ToolStripMenuItem] } | ForEach-Object Text)
                $texts | Should -Be @('Import &targets...', 'Import fi&ndings...', 'Run e&xternal scan...',
                    '&Export findings...', 'Export re&mediation...', 'Re&fresh', 'Open &Integrations tab')
                foreach ($k in 'MenuIntegrationImportTargets', 'MenuIntegrationImportFindings', 'MenuIntegrationRunScan',
                               'MenuIntegrationExportFindings', 'MenuIntegrationExportRemediation', 'MenuIntegrationRefresh') {
                    $menu.DropDownItems.Contains($form.Tag[$k]) | Should -BeTrue -Because "$k must live under the Integrations menu"
                }
            } finally { $form.Dispose() }
        }
    }

    It 'never makes an integration button the form AcceptButton' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                foreach ($k in 'IntegrationImportTargets', 'IntegrationImportFindings', 'IntegrationRunScan',
                               'IntegrationExportFindings', 'IntegrationExportRemediation') {
                    $form.AcceptButton | Should -Not -Be $form.Tag[$k]
                }
            } finally { $form.Dispose() }
        }
    }

    It 'shows the bundled Integrations folder as the default in a grey label' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $form.Tag['IntegrationPathDefault'].Text | Should -BeLike ('*' + (Get-WoscapPluginRoot) + '*')
                $form.Tag['IntegrationPathDefault'].ForeColor | Should -Be ([System.Drawing.SystemColors]::GrayText)
            } finally { $form.Dispose() }
        }
    }

    It 'starts with every action disabled and lists nothing before the tab is shown' {
        InModuleScope woscap -Parameters @{ Actions = $script:Actions } {
            param($Actions)
            Mock Get-WoscapIntegration { throw 'must not list at build time' }
            $form = New-WoscapMainForm
            try {
                foreach ($k in $Actions) {
                    $form.Tag[$k].Enabled | Should -BeFalse -Because "$k needs a selected plugin"
                    $form.Tag["Menu$k"].Enabled | Should -BeFalse -Because "Menu$k needs a selected plugin"
                }
                $form.Tag['IntegrationGrid'].Rows.Count | Should -Be 0
                Should -Invoke Get-WoscapIntegration -Times 0 -Exactly
            } finally { $form.Dispose() }
        }
    }

    It 'lists the bundled plugins on first selection of the tab (real Get-WoscapIntegration, blank folder)' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['IntegrationPath'].Text = '   '
                $form.Show(); [System.Windows.Forms.Application]::DoEvents()
                $t['Tabs'].SelectedTab = $t['IntegrationsTab']
                [System.Windows.Forms.Application]::DoEvents()
                $grid = $t['IntegrationGrid']
                @($grid.Rows | ForEach-Object { $_.Tag.Name } | Sort-Object) | Should -Be @('Ansible', 'OpenVAS', 'Zabbix')
                foreach ($r in $grid.Rows) {
                    $r.Cells[2].Value | Should -Be 'Yes'
                    $r.Tag.Path | Should -BeLike ((Get-WoscapPluginRoot) + '*')
                }
                $openvas = @($grid.Rows | Where-Object { $_.Tag.Name -eq 'OpenVAS' })[0]
                $openvas.Cells[1].Value | Should -Be '1.0.0'
                $openvas.Cells[3].Value | Should -Be 'Import-Findings, Invoke-ExternalScan'
                $t['IntegrationStatus'].Text | Should -Match '3'
                @($grid.SelectedRows).Count | Should -Be 0 -Because 'a fresh listing must not pre-select a plugin'
            } finally { $form.Close(); $form.Dispose() }
        }
    }

    It 'lists a Plugin folder with -Path, greys the non-conformant plugin and keeps it not actionable' {
        InModuleScope woscap -Parameters @{ Root = $script:PluginRoot; Actions = $script:Actions } {
            param($Root, $Actions)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['IntegrationPath'].Text = "  $Root  "
                Update-WoscapGuiIntegrationView -Tag $t
                $grid = $t['IntegrationGrid']
                @($grid.Rows | ForEach-Object { $_.Tag.Name } | Sort-Object) | Should -Be @('Broken', 'Good')
                $broken = @($grid.Rows | Where-Object { $_.Tag.Name -eq 'Broken' })[0]
                $broken.Cells[2].Value | Should -Be 'No'
                $broken.DefaultCellStyle.ForeColor | Should -Be ([System.Drawing.SystemColors]::GrayText)
                $good = @($grid.Rows | Where-Object { $_.Tag.Name -eq 'Good' })[0]
                $good.Cells[2].Value | Should -Be 'Yes'
                $good.DefaultCellStyle.ForeColor | Should -Not -Be ([System.Drawing.SystemColors]::GrayText)
                $t['IntegrationStatus'].Text | Should -Match '1 not conformant'

                $null = Select-TestPlugin $t 'Broken'
                foreach ($k in $Actions) {
                    $t[$k].Enabled | Should -BeFalse -Because "$k must not act on a non-conformant plugin"
                    $t["Menu$k"].Enabled | Should -BeFalse
                }
                $null = Select-TestPlugin $t 'Good'
                $t['IntegrationImportTargets'].Enabled | Should -BeTrue
                $t['MenuIntegrationImportTargets'].Enabled | Should -BeTrue
            } finally { $form.Dispose() }
        }
    }

    It 'enables exactly the <Plugin> capabilities on button and menu together' -ForEach $script:BundledCases {
        InModuleScope woscap -Parameters @{ Plugin = $Plugin; Enabled = $Enabled; Actions = $script:Actions } {
            param($Plugin, $Enabled, $Actions)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                Update-WoscapGuiIntegrationView -Tag $t
                $null = Select-TestPlugin $t $Plugin
                foreach ($k in $Actions) {
                    $want = $k -in $Enabled
                    $t[$k].Enabled | Should -Be $want -Because "$k for $Plugin"
                    $t["Menu$k"].Enabled | Should -Be $want -Because "Menu$k must match its button for $Plugin"
                }
            } finally { $form.Dispose() }
        }
    }

    It 'clears the selection and disables every action after a refresh' {
        InModuleScope woscap -Parameters @{ Actions = $script:Actions } {
            param($Actions)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $form.Show(); [System.Windows.Forms.Application]::DoEvents()
                Update-WoscapGuiIntegrationView -Tag $t
                $null = Select-TestPlugin $t 'Ansible'
                $t['IntegrationImportTargets'].Enabled | Should -BeTrue
                Invoke-WoscapTestClick $t['IntegrationRefresh']
                [System.Windows.Forms.Application]::DoEvents()
                @($t['IntegrationGrid'].SelectedRows).Count | Should -Be 0
                foreach ($k in $Actions) { $t[$k].Enabled | Should -BeFalse -Because "$k after a refresh rebinds the grid" }
            } finally { $form.Close(); $form.Dispose() }
        }
    }

    It 'disables every action while an integration or content job runs, whatever is selected' {
        InModuleScope woscap -Parameters @{ Actions = $script:Actions } {
            param($Actions)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                Update-WoscapGuiIntegrationView -Tag $t
                $null = Select-TestPlugin $t 'Ansible'
                foreach ($busy in 'Integration', 'Content') {
                    $t['Busy'] = $busy
                    Update-WoscapGuiIntegrationSelection -Tag $t
                    foreach ($k in $Actions) { $t[$k].Enabled | Should -BeFalse -Because "$k while Busy=$busy" }
                }
                $t['Busy'] = $null
                Update-WoscapGuiIntegrationSelection -Tag $t
                $t['IntegrationImportTargets'].Enabled | Should -BeTrue
            } finally { $form.Dispose() }
        }
    }

    It 'Refresh button and Refresh menu re-list the Plugin folder' {
        InModuleScope woscap -Parameters @{ Root = $script:PluginRoot } {
            param($Root)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['IntegrationPath'].Text = $Root
                Invoke-WoscapTestClick $t['IntegrationRefresh']
                $t['IntegrationGrid'].Rows.Count | Should -Be 2
                Microsoft.PowerShell.Management\Remove-Item -LiteralPath (Join-Path $Root 'Broken') -Recurse -Force
                $t['MenuIntegrationRefresh'].PerformClick()
                $t['IntegrationGrid'].Rows.Count | Should -Be 1
            } finally { $form.Dispose() }
        }
    }

    It 'lists only on the first selection of the tab' {
        InModuleScope woscap {
            Mock Get-WoscapIntegration { }
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $form.Show(); [System.Windows.Forms.Application]::DoEvents()
                $t['Tabs'].SelectedTab = $t['IntegrationsTab']
                $t['Tabs'].SelectedTab = $t['ScanTab']
                $t['Tabs'].SelectedTab = $t['IntegrationsTab']
                Should -Invoke Get-WoscapIntegration -Times 1 -Exactly
            } finally { $form.Close(); $form.Dispose() }
        }
    }

    It 'reports a missing Plugin folder in the status line, clears the grid and never throws' {
        InModuleScope woscap -Parameters @{ Root = $script:PluginRoot } {
            param($Root)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['IntegrationPath'].Text = $Root
                Update-WoscapGuiIntegrationView -Tag $t
                $t['IntegrationGrid'].Rows.Count | Should -Be 2
                $t['IntegrationPath'].Text = Join-Path $Root 'nope'
                { Update-WoscapGuiIntegrationView -Tag $t } | Should -Not -Throw
                $t['IntegrationGrid'].Rows.Count | Should -Be 0
                $t['IntegrationStatus'].Text | Should -Match 'not found'
                Should -Invoke Show-WoscapGuiMessage -Times 0 -Exactly
            } finally { $form.Dispose() }
        }
    }

    It 'reports a listing error in the status line and never throws' {
        InModuleScope woscap {
            Mock Get-WoscapIntegration { throw 'folder is unreadable' }
            $form = New-WoscapMainForm
            try {
                { Update-WoscapGuiIntegrationView -Tag $form.Tag } | Should -Not -Throw
                $form.Tag['IntegrationStatus'].Text | Should -Match 'folder is unreadable'
                $form.Tag['IntegrationGrid'].Rows.Count | Should -Be 0
            } finally { $form.Dispose() }
        }
    }

    It 'passes the trimmed Plugin folder as -Path and omits it when blank' {
        InModuleScope woscap -Parameters @{ Root = $script:PluginRoot } {
            param($Root)
            $script:listCalls = [System.Collections.Generic.List[object]]::new()
            Mock Get-WoscapIntegration { $script:listCalls.Add(@{ Path = $Path }) }
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['IntegrationPath'].Text = "  $Root "
                Update-WoscapGuiIntegrationView -Tag $t
                $t['IntegrationPath'].Text = ''
                Update-WoscapGuiIntegrationView -Tag $t
                $script:listCalls.Count | Should -Be 2
                $script:listCalls[0].Path | Should -Be $Root
                $script:listCalls[1].Path | Should -BeNullOrEmpty -Because 'a blank folder means the bundled Integrations folder'
            } finally { $form.Dispose() }
        }
    }

    It 'Browse sets the Plugin folder from the folder seam and re-lists' {
        InModuleScope woscap -Parameters @{ Root = $script:PluginRoot } {
            param($Root)
            Mock Get-WoscapGuiFolderPath { $Root }.GetNewClosure()
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                Invoke-WoscapTestClick $t['IntegrationPathBrowse']
                $t['IntegrationPath'].Text | Should -Be $Root
                $t['IntegrationGrid'].Rows.Count | Should -Be 2
            } finally { $form.Dispose() }
        }
    }

    It 'Browse cancelled leaves the Plugin folder unchanged and does not list' {
        InModuleScope woscap {
            Mock Get-WoscapIntegration { throw 'must not list' }
            $form = New-WoscapMainForm
            try {
                $form.Tag['IntegrationPath'].Text = 'C:\keep'
                Invoke-WoscapTestClick $form.Tag['IntegrationPathBrowse']
                Should -Invoke Get-WoscapGuiFolderPath -Times 1 -Exactly
                $form.Tag['IntegrationPath'].Text | Should -Be 'C:\keep'
                Should -Invoke Get-WoscapIntegration -Times 0 -Exactly
            } finally { $form.Dispose() }
        }
    }

    It 'refuses to act on a selected plugin once the Plugin folder was edited since the listing' {
        InModuleScope woscap -Parameters @{ Root = $script:PluginRoot } {
            param($Root)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['IntegrationPath'].Text = $Root
                Update-WoscapGuiIntegrationView -Tag $t
                $null = Select-TestPlugin $t 'Good'
                $ok = Get-WoscapGuiIntegrationTarget -Tag $t -Hook 'Get-Targets'
                $ok.Plugin.Name | Should -Be 'Good'
                $ok.PluginPath | Should -Be (Join-Path $Root 'Good')

                $t['IntegrationPath'].Text = ''
                Get-WoscapGuiIntegrationTarget -Tag $t -Hook 'Get-Targets' | Should -BeNullOrEmpty
                Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly -ParameterFilter { $Text -match 'Refresh' }
            } finally { $form.Dispose() }
        }
    }

    It 'passes the bundled plugin''s own folder as PluginPath when the folder is blank' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                Update-WoscapGuiIntegrationView -Tag $t
                $null = Select-TestPlugin $t 'OpenVAS'
                $r = Get-WoscapGuiIntegrationTarget -Tag $t -Hook 'Import-Findings'
                $r.Plugin.Name | Should -Be 'OpenVAS'
                $r.PluginPath | Should -Be (Join-Path (Get-WoscapPluginRoot) 'OpenVAS')
            } finally { $form.Dispose() }
        }
    }

    It 'refuses a hook the selected plugin does not declare and a non-conformant plugin' {
        InModuleScope woscap -Parameters @{ Root = $script:PluginRoot } {
            param($Root)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['IntegrationPath'].Text = $Root
                Update-WoscapGuiIntegrationView -Tag $t
                $null = Select-TestPlugin $t 'Good'
                Get-WoscapGuiIntegrationTarget -Tag $t -Hook 'Export-Findings' | Should -BeNullOrEmpty
                $null = Select-TestPlugin $t 'Broken'
                Get-WoscapGuiIntegrationTarget -Tag $t -Hook 'Get-Targets' | Should -BeNullOrEmpty
            } finally { $form.Dispose() }
        }
    }

    It 'keeps every visible Integrations-tab control inside its parent at default and minimum size' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $form.Show(); [System.Windows.Forms.Application]::DoEvents()
                $t['Tabs'].SelectedTab = $t['IntegrationsTab']
                [System.Windows.Forms.Application]::DoEvents()
                $t['IntegrationGrid'].Rows.Count | Should -Be 3
                [void]$t['IntegrationGrid'].Rows.Add([object[]]@(('VeryLongPluginName' * 12), '1.0.0', 'Yes', ('Get-Targets, ' * 10)))
                $t['IntegrationPathDefault'].Text = 'Default: C:\' + ('very\long\path\' * 30)
                $t['IntegrationPath'].Text = 'C:\' + ('long\' * 60)
                $t['IntegrationStatus'].Text = 'A long status message ' * 20
                $walk = { param($c) foreach ($child in $c.Controls) { $child; & $walk $child } }
                $bad = [System.Collections.Generic.List[string]]::new()
                $checked = 0
                foreach ($size in $form.Size, $form.MinimumSize) {
                    $form.Size = $size
                    [System.Windows.Forms.Application]::DoEvents()
                    foreach ($c in @(& $walk $t['IntegrationsTab'])) {
                        if (-not $c.Visible) { continue }
                        $checked++
                        $w = $c.Parent.ClientSize.Width
                        $h = $c.Parent.ClientSize.Height
                        if ($c.Left -lt 0 -or $c.Right -gt $w -or $c.Top -lt 0 -or $c.Bottom -gt $h) {
                            $bad.Add(('{0} "{1}" L={2} R={3} T={4} B={5} parent={6}x{7} at {8}x{9}' -f
                                $c.GetType().Name, $c.Text, $c.Left, $c.Right, $c.Top, $c.Bottom, $w, $h, $size.Width, $size.Height))
                        }
                    }
                    foreach ($k in 'IntegrationImportTargets', 'IntegrationImportFindings', 'IntegrationRunScan',
                                   'IntegrationExportFindings', 'IntegrationExportRemediation', 'IntegrationRefresh', 'IntegrationPathBrowse') {
                        $b = $t[$k]
                        $r = $t['IntegrationsTab'].RectangleToClient($b.RectangleToScreen($b.ClientRectangle))
                        if ($r.Left -lt 0 -or $r.Right -gt $t['IntegrationsTab'].ClientSize.Width -or $r.Bottom -gt $t['IntegrationsTab'].ClientSize.Height) {
                            $bad.Add(('{0} outside the tab: R={1} B={2} tab={3}x{4}' -f $k, $r.Right, $r.Bottom,
                                $t['IntegrationsTab'].ClientSize.Width, $t['IntegrationsTab'].ClientSize.Height))
                        }
                    }
                }
                $checked | Should -BeGreaterThan 10
                $bad | Should -BeNullOrEmpty -Because 'no Integrations-tab control may overflow its parent'
            } finally { $form.Close(); $form.Dispose() }
        }
    }
}

Describe 'Busy interplay with the Integration job' -Skip:(-not $script:IsSta) {
    BeforeEach {
        Mock -ModuleName woscap Show-WoscapGuiMessage { }
        Mock -ModuleName woscap Get-WoscapGuiCredential { }
        Mock -ModuleName woscap Show-WoscapGuiDownloadDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiUpdateDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiRemoveDialog { $null }
        Mock -ModuleName woscap Get-WoscapGuiFolderPath { $null }
        Mock -ModuleName woscap Get-WoscapGuiOpenPath { @() }
        Mock -ModuleName woscap Invoke-WoscapGuiScan { throw 'the runner must not start' }
        Mock -ModuleName woscap Get-WoscapBenchmark { }
    }

    It 'content actions refuse with an integration message while Busy is Integration' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $form.Tag['Busy'] = 'Integration'
                Invoke-WoscapGuiContentDownload -Tag $form.Tag
                Should -Invoke Show-WoscapGuiDownloadDialog -Times 0 -Exactly
                Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly -ParameterFilter { $Text -match 'integration' }
            } finally { $form.Dispose() }
        }
    }

    It 'Set-WoscapGuiIntegrationBusy disables Run, Remediate and every content action, then restores them' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['Results'].Add([pscustomobject]@{ Host = 'h'; StigId = 'R-1'; Status = 'Open' })
                $t['ResultsContext'] = @{ Benchmark = 'Windows11'; ContentPath = '' }
                Set-WoscapGuiIntegrationBusy -Tag $t -Busy $true -Status 'Working...'
                $t['Busy'] | Should -Be 'Integration'
                $t['IntegrationStatus'].Text | Should -Be 'Working...'
                foreach ($k in 'Run', 'Remediate', 'ContentDownload', 'ContentUpdate', 'ContentRemove', 'ContentUseForScan') {
                    $t[$k].Enabled | Should -BeFalse -Because "$k during an integration job"
                    $t["Menu$k"].Enabled | Should -BeFalse -Because "Menu$k during an integration job"
                }
                Set-WoscapGuiIntegrationBusy -Tag $t -Busy $false
                $t['Busy'] | Should -BeNullOrEmpty
                foreach ($k in 'Run', 'Remediate', 'ContentDownload', 'ContentUpdate') {
                    $t[$k].Enabled | Should -BeTrue -Because "$k after the integration job"
                    $t["Menu$k"].Enabled | Should -BeTrue
                }
            } finally { $form.Dispose() }
        }
    }
}

Describe 'Relative Plugin folder' -Skip:(-not $script:IsSta) {
    BeforeEach {
        Mock -ModuleName woscap Show-WoscapGuiMessage { }
        Mock -ModuleName woscap Get-WoscapGuiCredential { }
        Mock -ModuleName woscap Get-WoscapGuiFolderPath { $null }
        Mock -ModuleName woscap Get-WoscapGuiOpenPath { @() }
        Mock -ModuleName woscap Get-WoscapGuiSavePath { $null }
        Mock -ModuleName woscap Invoke-WoscapGuiScan { throw 'the runner must not start' }
        Mock -ModuleName woscap Get-WoscapBenchmark { }
    }

    It 'resolves a relative folder against the PowerShell location, not the process directory' {
        $base = Join-Path $TestDrive ('rel-' + [guid]::NewGuid().ToString('N'))
        $null = New-TestPluginRoot (Join-Path $base 'plugs')
        $decoy = Join-Path $TestDrive ('decoy-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $decoy -Force | Out-Null
        $savedCwd = [Environment]::CurrentDirectory
        Push-Location -LiteralPath $base
        try {
            [Environment]::CurrentDirectory = $decoy
            InModuleScope woscap -Parameters @{ Base = $base } {
                param($Base)
                $form = New-WoscapMainForm
                try {
                    $t = $form.Tag
                    $t['IntegrationPath'].Text = 'plugs'
                    Update-WoscapGuiIntegrationView -Tag $t
                    @($t['IntegrationGrid'].Rows | ForEach-Object { $_.Tag.Name } | Sort-Object) | Should -Be @('Broken', 'Good')
                    $t['IntegrationListedRoot'] | Should -Be (Join-Path $Base 'plugs')
                    $g = $t['IntegrationGrid']; $g.ClearSelection()
                    @($g.Rows | Where-Object { $_.Tag.Name -eq 'Good' })[0].Selected = $true
                    $r = Get-WoscapGuiIntegrationTarget -Tag $t -Hook 'Get-Targets'
                    $r | Should -Not -BeNullOrEmpty -Because 'the guard must resolve the box the same way the listing did'
                    $r.PluginPath | Should -Be (Join-Path (Join-Path $Base 'plugs') 'Good')
                    Should -Invoke Show-WoscapGuiMessage -Times 0 -Exactly
                } finally { $form.Dispose() }
            }
        } finally {
            Pop-Location
            [Environment]::CurrentDirectory = $savedCwd
        }
    }
}

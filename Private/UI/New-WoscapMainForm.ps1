function New-WoscapMainForm {
    <#
        Builds and wires the woscap main window and returns it WITHOUT showing it
        (Show-WoscapGui calls .ShowDialog()). Menu bar over a tabbed window. Pure
        presentation: every action calls a cmdlet or a named helper. Key controls + the
        full result set are exposed via $form.Tag for the handlers and the smoke tests.
    #>
    [CmdletBinding()]
    [OutputType([System.Windows.Forms.Form])]
    param()

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'woscap - STIG scanner'
    $form.Size = New-Object System.Drawing.Size(900, 700)
    $form.MinimumSize = New-Object System.Drawing.Size(760, 560)
    $form.StartPosition = 'CenterScreen'

    # Dropdown vocabularies are derived from their canonical owners so they cannot drift (#47).
    $scan = New-WoscapGuiScanTab -Vocabulary (Get-WoscapGuiVocabulary)
    $menu = New-WoscapGuiMenu

    $placeholder = {
        param([string] $Title, [string] $Text)
        $page = New-Object System.Windows.Forms.TabPage
        $page.Text = $Title
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $Text; $label.Location = '12,12'; $label.AutoSize = $true
        $page.Controls.Add($label)
        $page
    }
    $contentTab      = & $placeholder 'Content' 'Content management - coming in #17.'
    $integrationsTab = & $placeholder 'Integrations' 'Integrations - coming in #18.'

    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = 'Fill'
    $tabs.TabPages.AddRange(@($scan.TabPage, $contentTab, $integrationsTab))

    # Dock order: the last-added control docks first, so the menu claims the top strip.
    $form.Controls.Add($tabs)
    $form.Controls.Add($menu.Menu)
    $form.MainMenuStrip = $menu.Menu

    $tag = @{
        Menu = $menu.Menu; MenuRun = $menu.Run; MenuExport = $menu.Export
        Tabs = $tabs; ScanTab = $scan.TabPage; ContentTab = $contentTab; IntegrationsTab = $integrationsTab
        # Non-modal channel for partial-scan warning detail (see the OnWarning handler).
        StatusTip = New-Object System.Windows.Forms.ToolTip
        AdvancedExpanded = $false
        Results = [System.Collections.Generic.List[object]]::new()
    }
    foreach ($key in $scan.Keys) { if ($key -ne 'TabPage') { $tag[$key] = $scan[$key] } }
    $form.Tag = $tag

    Set-WoscapGuiActionEnabled -Tag $tag -Action Export -Enabled $false
    Update-WoscapGuiProfileButton -Tag $tag
    Update-WoscapGuiContentHint -Tag $tag

    # Single-window: the current form's controls, for the plain event scriptblocks below.
    $script:WoscapGuiTag = $tag

    # Event handlers are PLAIN scriptblocks (no .GetNewClosure()) so they keep the module's
    # session state and resolve the named helpers; all logic lives in those helpers.
    $scan.XccdfBrowse.Add_Click({
        $t = $script:WoscapGuiTag
        $p = @(Get-WoscapGuiOpenPath -Filter 'XCCDF (*.xml)|*.xml|All files|*.*')
        if ($p.Count -gt 0) { $t['Xccdf'].Text = $p[0] }
    })
    $scan.ProfileAdd.Add_Click({ Invoke-WoscapGuiProfileAdd -Tag $script:WoscapGuiTag })
    $scan.ProfileRemove.Add_Click({ Remove-WoscapGuiProfile -Tag $script:WoscapGuiTag })
    $scan.ProfileUp.Add_Click({ Move-WoscapGuiProfile -Tag $script:WoscapGuiTag -Offset -1 })
    $scan.ProfileDown.Add_Click({ Move-WoscapGuiProfile -Tag $script:WoscapGuiTag -Offset 1 })
    $scan.Profiles.Add_SelectedIndexChanged({ Update-WoscapGuiProfileButton -Tag $script:WoscapGuiTag })

    $scan.AdvancedToggle.Add_Click({
        $t = $script:WoscapGuiTag
        Set-WoscapGuiAdvanced -Tag $t -Expanded (-not $t['AdvancedExpanded'])
    })
    $scan.ContentBrowse.Add_Click({
        $t = $script:WoscapGuiTag
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $t['ContentPath'].Text = $dlg.SelectedPath }
    })
    $scan.JsonBrowse.Add_Click({
        $t = $script:WoscapGuiTag
        $p = Get-WoscapGuiSavePath -Format 'json'
        if ($p) { $t['JsonPath'].Text = $p }
    })
    $scan.Benchmark.Add_SelectedIndexChanged({ Update-WoscapGuiContentHint -Tag $script:WoscapGuiTag })

    $scan.FilterSeverity.Add_SelectedIndexChanged({ Update-WoscapGuiView -Tag $script:WoscapGuiTag })
    $scan.FilterStatus.Add_SelectedIndexChanged({ Update-WoscapGuiView -Tag $script:WoscapGuiTag })
    $scan.Find.Add_TextChanged({ Update-WoscapGuiView -Tag $script:WoscapGuiTag })

    $scan.Run.Add_Click({ Invoke-WoscapGuiRun -Tag $script:WoscapGuiTag })
    $scan.Export.Add_Click({ Invoke-WoscapGuiExport -Tag $script:WoscapGuiTag })

    $menu.Run.Add_Click({ Invoke-WoscapGuiRun -Tag $script:WoscapGuiTag })
    $menu.Export.Add_Click({ Invoke-WoscapGuiExport -Tag $script:WoscapGuiTag })
    $menu.Exit.Add_Click({ $script:WoscapGuiTag['Tabs'].FindForm().Close() })
    $menu.Advanced.Add_Click({ Show-WoscapGuiAdvancedOption -Tag $script:WoscapGuiTag })
    $menu.OpenContent.Add_Click({ $t = $script:WoscapGuiTag; $t['Tabs'].SelectedTab = $t['ContentTab'] })
    $menu.OpenIntegrations.Add_Click({ $t = $script:WoscapGuiTag; $t['Tabs'].SelectedTab = $t['IntegrationsTab'] })
    $menu.Manual.Add_Click({ Open-WoscapGuiManual })
    $menu.About.Add_Click({ Show-WoscapGuiAbout })

    # Release the module-scoped reference when the window closes so the form and results
    # do not stay reachable for the rest of the session.
    $form.Add_FormClosed({ $script:WoscapGuiTag = $null })

    $form
}

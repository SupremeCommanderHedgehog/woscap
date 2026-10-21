function New-WoscapGuiIntegrationTab {
    <#
        Builds the Integrations TabPage: Plugin folder + default-root hint, the plugin grid and
        the action buttons with a status line. Layout-panel built (no absolute coordinates).
        Returns a hashtable: TabPage plus every control the handlers/tests need, keyed by its
        Tag name. No wiring here.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = 'Integrations'

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'; $layout.ColumnCount = 2
    $layout.Padding = New-Object System.Windows.Forms.Padding(6)
    [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    # Ellipsized rather than AutoSize so a long path or message cannot widen its row.
    $newHint = {
        $l = New-Object System.Windows.Forms.Label
        $l.AutoSize = $false; $l.AutoEllipsis = $true; $l.Dock = 'Fill'
        $l.Height = $l.PreferredHeight
        $l
    }

    # --- Plugin folder [....] [Browse...] ---
    $path = New-Object System.Windows.Forms.TextBox
    $path.Anchor = 'Left, Right'
    $browse = New-Object System.Windows.Forms.Button
    $browse.Text = 'Browse...'; $browse.AutoSize = $true
    $pathStrip = New-Object System.Windows.Forms.TableLayoutPanel
    $pathStrip.ColumnCount = 2; $pathStrip.RowCount = 1
    $pathStrip.Dock = 'Fill'; $pathStrip.AutoSize = $true; $pathStrip.AutoSizeMode = 'GrowAndShrink'
    $pathStrip.Margin = New-Object System.Windows.Forms.Padding(0)
    [void]$pathStrip.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$pathStrip.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $pathStrip.Controls.Add($path, 0, 0)
    $pathStrip.Controls.Add($browse, 1, 0)

    $default = & $newHint
    $default.ForeColor = [System.Drawing.SystemColors]::GrayText
    $default.Text = 'Default: ' + (Get-WoscapPluginRoot)

    $grid = New-WoscapGuiContentGrid -Header 'Name', 'Version', 'Conformant', 'Capabilities' `
        -Property 'Name', 'Version', 'Conformant', 'Capabilities' -Rows @()
    $grid.MultiSelect = $false

    # Wrapping strip: six buttons do not fit one row at the minimum window width.
    $buttons = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttons.Dock = 'Fill'; $buttons.AutoSize = $true; $buttons.AutoSizeMode = 'GrowAndShrink'; $buttons.WrapContents = $true
    $buttons.Margin = New-Object System.Windows.Forms.Padding(0)
    $newButton = {
        param([string] $Text)
        $b = New-Object System.Windows.Forms.Button
        $b.Text = $Text; $b.AutoSize = $true
        $b
    }
    $importTargets  = & $newButton 'Import targets...'
    $importFindings = & $newButton 'Import findings...'
    $runScan        = & $newButton 'Run external scan...'
    $exportFindings = & $newButton 'Export findings...'
    $exportRemed    = & $newButton 'Export remediation...'
    $refresh        = & $newButton 'Refresh'
    $buttons.Controls.AddRange(@($importTargets, $importFindings, $runScan, $exportFindings, $exportRemed, $refresh))
    $status = & $newHint

    Add-WoscapGuiContentRow -Layout $layout -Label 'Plugin folder:' -Control $pathStrip
    Add-WoscapGuiContentRow -Layout $layout -Label ' ' -Control $default
    Add-WoscapGuiContentRow -Layout $layout -Control $grid -Fill
    Add-WoscapGuiContentRow -Layout $layout -Control $buttons
    Add-WoscapGuiContentRow -Layout $layout -Control $status
    $page.Controls.Add($layout)

    @{
        TabPage = $page
        IntegrationPath = $path; IntegrationPathBrowse = $browse; IntegrationPathDefault = $default
        IntegrationGrid = $grid
        IntegrationImportTargets = $importTargets; IntegrationImportFindings = $importFindings
        IntegrationRunScan = $runScan; IntegrationExportFindings = $exportFindings
        IntegrationExportRemediation = $exportRemed; IntegrationRefresh = $refresh; IntegrationStatus = $status
    }
}

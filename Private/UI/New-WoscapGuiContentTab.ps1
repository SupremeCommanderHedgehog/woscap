function New-WoscapGuiContentTab {
    <#
        Builds the Content TabPage: Cache folder + default-root hint, benchmark filter, the
        cached-benchmark grid, and the action buttons with a status line. Layout-panel built
        (no absolute coordinates). Returns a hashtable: TabPage plus every control the
        handlers/tests need, keyed by its Tag name. No wiring here.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = 'Content'

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'; $layout.ColumnCount = 2
    $layout.Padding = New-Object System.Windows.Forms.Padding(6)
    [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    # One-row, two-column strip; the stretching column absorbs spare width.
    $newStrip = {
        param([int] $StretchColumn)
        $p = New-Object System.Windows.Forms.TableLayoutPanel
        $p.ColumnCount = 2; $p.RowCount = 1
        $p.Dock = 'Fill'; $p.AutoSize = $true; $p.AutoSizeMode = 'GrowAndShrink'
        $p.Margin = New-Object System.Windows.Forms.Padding(0)
        foreach ($i in 0, 1) {
            $style = if ($i -eq $StretchColumn) {
                New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)
            } else { New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize) }
            [void]$p.ColumnStyles.Add($style)
        }
        [void]$p.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
        $p
    }
    # Ellipsized rather than AutoSize so a long path or message cannot widen its row.
    $newHint = {
        $l = New-Object System.Windows.Forms.Label
        $l.AutoSize = $false; $l.AutoEllipsis = $true; $l.Anchor = 'Left, Right'
        $l.Height = $l.PreferredHeight
        $l
    }

    # --- Cache folder [....] [Browse...] ---
    $destination = New-Object System.Windows.Forms.TextBox
    $destination.Anchor = 'Left, Right'
    $browse = New-Object System.Windows.Forms.Button
    $browse.Text = 'Browse...'; $browse.AutoSize = $true
    $destinationStrip = & $newStrip 0
    $destinationStrip.Controls.Add($destination, 0, 0)
    $destinationStrip.Controls.Add($browse, 1, 0)

    $default = & $newHint
    $default.ForeColor = [System.Drawing.SystemColors]::GrayText
    $default.Text = 'Default: ' + (Get-WoscapContentCacheRoot)

    # --- Benchmark filter ---
    $filter = New-Object System.Windows.Forms.ComboBox
    $filter.DropDownStyle = 'DropDownList'; $filter.Width = 220; $filter.Anchor = 'Left'
    [void]$filter.Items.Add('All'); $filter.SelectedIndex = 0

    # --- Grid ---
    $grid = New-WoscapGuiContentGrid -Header 'Benchmark', 'Revision', 'Title', 'Content hash', 'Source URL' `
        -Property 'Benchmark', 'Revision', 'Title', 'ContentHash', 'SourceUrl' -Rows @()
    $grid.MultiSelect = $false

    # --- [Download...] [Update...] [Remove...] [Use for scan] [Refresh]   status ---
    $buttons = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttons.AutoSize = $true; $buttons.AutoSizeMode = 'GrowAndShrink'; $buttons.WrapContents = $false
    $buttons.Margin = New-Object System.Windows.Forms.Padding(0)
    $newButton = {
        param([string] $Text)
        $b = New-Object System.Windows.Forms.Button
        $b.Text = $Text; $b.AutoSize = $true
        $b
    }
    $download  = & $newButton 'Download...'
    $update    = & $newButton 'Update...'
    $remove    = & $newButton 'Remove...'
    $useForScan = & $newButton 'Use for scan'
    $refresh   = & $newButton 'Refresh'
    $buttons.Controls.AddRange(@($download, $update, $remove, $useForScan, $refresh))
    $status = & $newHint
    $actionStrip = & $newStrip 1
    $actionStrip.Controls.Add($buttons, 0, 0)
    $actionStrip.Controls.Add($status, 1, 0)

    Add-WoscapGuiContentRow -Layout $layout -Label 'Cache folder:' -Control $destinationStrip
    Add-WoscapGuiContentRow -Layout $layout -Label ' ' -Control $default
    Add-WoscapGuiContentRow -Layout $layout -Label 'Benchmark filter:' -Control $filter
    Add-WoscapGuiContentRow -Layout $layout -Control $grid -Fill
    Add-WoscapGuiContentRow -Layout $layout -Control $actionStrip
    $page.Controls.Add($layout)

    @{
        TabPage = $page
        ContentDestination = $destination; ContentDestinationBrowse = $browse; ContentDestinationDefault = $default
        ContentFilter = $filter; ContentGrid = $grid
        ContentDownload = $download; ContentUpdate = $update; ContentRemove = $remove
        ContentUseForScan = $useForScan; ContentRefresh = $refresh; ContentStatus = $status
    }
}

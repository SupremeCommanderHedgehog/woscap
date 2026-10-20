function New-WoscapGuiScanTab {
    <#
        Builds the Scan TabPage. Rows are fixed-height panels in a one-column
        TableLayoutPanel with AutoSize rows, so hiding the Advanced row collapses it and
        the rows below reflow; the grid row takes the remaining height.
        Returns a hashtable: TabPage plus every control the handlers/tests need.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][hashtable] $Vocabulary)

    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = 'Scan'

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'
    $layout.ColumnCount = 1
    [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))

    # Child coordinates below are designed for the row width at the form's default size.
    # Containers must start at that width: anchors capture right-edge gaps when children are added.
    $designWidth = 876

    $newRow = {
        param([int] $Height)
        $p = New-Object System.Windows.Forms.Panel
        $p.Size = New-Object System.Drawing.Size($designWidth, $Height)
        $p.Anchor = 'Left, Right'
        $p.Margin = New-Object System.Windows.Forms.Padding(0)
        $p
    }
    $newLabel = {
        param([string] $Text, [string] $Location)
        $l = New-Object System.Windows.Forms.Label
        $l.Text = $Text; $l.Location = $Location; $l.AutoSize = $true
        $l
    }
    $newButton = {
        param([string] $Text, [string] $Location, [int] $Width)
        $b = New-Object System.Windows.Forms.Button
        $b.Text = $Text; $b.Location = $Location; $b.Width = $Width
        $b
    }

    # --- Inputs: benchmark/XCCDF, targets/profiles, credential/Run ---
    $inputs = & $newRow 150
    $benchmark = New-Object System.Windows.Forms.ComboBox
    $benchmark.DropDownStyle = 'DropDownList'; $benchmark.Location = '90,8'; $benchmark.Width = 140
    $contentRoot = Join-Path $script:WoscapModuleRoot 'Content'
    if (Test-Path -LiteralPath $contentRoot) {
        foreach ($d in (Get-ChildItem -LiteralPath $contentRoot -Directory | Sort-Object Name)) {
            [void]$benchmark.Items.Add($d.Name)
        }
    }
    # Default to Windows11: the alphabetically-first app pack would silently scan a Windows
    # XCCDF against the wrong descriptors.
    if ($benchmark.Items.Count -gt 0) {
        $win = $benchmark.Items.IndexOf('Windows11')
        $benchmark.SelectedIndex = if ($win -ge 0) { $win } else { 0 }
    }
    $xccdf = New-Object System.Windows.Forms.TextBox
    $xccdf.Location = '300,8'; $xccdf.Width = 420; $xccdf.ReadOnly = $true; $xccdf.Anchor = 'Top, Left, Right'
    $xccdfBrowse = & $newButton 'Browse...' '730,6' 80
    $xccdfBrowse.Anchor = 'Top, Right'

    $targets = New-Object System.Windows.Forms.TextBox
    $targets.Location = '90,41'; $targets.Width = 140

    $profiles = New-Object System.Windows.Forms.ListBox
    $profiles.Location = '300,41'; $profiles.Size = New-Object System.Drawing.Size(420, 70)
    $profiles.Anchor = 'Top, Left, Right'; $profiles.HorizontalScrollbar = $true
    $profileAdd    = & $newButton 'Add...' '730,39' 80
    $profileRemove = & $newButton 'Remove' '730,64' 80
    $profileUp     = & $newButton 'Up' '730,89' 38
    $profileDown   = & $newButton 'Down' '772,89' 38
    foreach ($b in $profileAdd, $profileRemove, $profileUp, $profileDown) { $b.Anchor = 'Top, Right' }

    $useCred = New-Object System.Windows.Forms.CheckBox
    $useCred.Text = 'Use alternate credential'; $useCred.Location = '90,120'; $useCred.AutoSize = $true
    $run = & $newButton 'Run' '730,117' 80
    $run.Anchor = 'Top, Right'

    $inputs.Controls.AddRange(@(
        (& $newLabel 'Benchmark:' '12,11'), $benchmark, (& $newLabel 'XCCDF:' '250,11'), $xccdf, $xccdfBrowse,
        (& $newLabel 'Targets:' '12,44'), $targets, (& $newLabel 'Profiles:' '245,44'), $profiles,
        $profileAdd, $profileRemove, $profileUp, $profileDown, $useCred, $run
    ))

    # --- Advanced toggle + group ---
    $toggleRow = & $newRow 30
    $advancedToggle = & $newButton '[+] Advanced' '12,3' 110
    $toggleRow.Controls.Add($advancedToggle)

    $advancedGroup = New-Object System.Windows.Forms.GroupBox
    $advancedGroup.Text = 'Advanced'
    $advancedGroup.Size = New-Object System.Drawing.Size(($designWidth - 6), 110)   # minus its 3px side margins
    $advancedGroup.Anchor = 'Left, Right'; $advancedGroup.Visible = $false
    $contentPath = New-Object System.Windows.Forms.TextBox
    $contentPath.Location = '110,20'; $contentPath.Width = 600; $contentPath.Anchor = 'Top, Left, Right'
    $contentBrowse = & $newButton 'Browse...' '720,18' 80
    $contentBrowse.Anchor = 'Top, Right'
    # TextBox.PlaceholderText is .NET Core-only; a label shows the default on 5.1 too.
    $contentPathDefault = & $newLabel '' '110,44'
    $contentPathDefault.ForeColor = [System.Drawing.SystemColors]::GrayText
    $throttle = New-Object System.Windows.Forms.NumericUpDown
    $throttle.Location = '110,72'; $throttle.Width = 60
    $throttle.Minimum = 1; $throttle.Maximum = 64
    $throttle.Value = (Get-WoscapGuiScanDefault).ThrottleLimit
    $jsonPath = New-Object System.Windows.Forms.TextBox
    $jsonPath.Location = '300,72'; $jsonPath.Width = 410; $jsonPath.Anchor = 'Top, Left, Right'
    $jsonBrowse = & $newButton 'Browse...' '720,70' 80
    $jsonBrowse.Anchor = 'Top, Right'
    $advancedGroup.Controls.AddRange(@(
        (& $newLabel 'Content path:' '10,23'), $contentPath, $contentBrowse, $contentPathDefault,
        (& $newLabel 'Throttle limit:' '10,75'), $throttle,
        (& $newLabel 'JSON output:' '210,75'), $jsonPath, $jsonBrowse
    ))

    # --- Progress ---
    $progressRow = & $newRow 30
    $progress = New-Object System.Windows.Forms.ProgressBar
    $progress.Location = '12,4'; $progress.Width = 620; $progress.Style = 'Continuous'; $progress.Anchor = 'Top, Left, Right'
    $status = & $newLabel '' '640,6'
    $status.Anchor = 'Top, Right'
    $progressRow.Controls.AddRange(@($progress, $status))

    # --- Filters ---
    $filterRow = & $newRow 32
    $filterSeverity = New-Object System.Windows.Forms.ComboBox
    $filterSeverity.DropDownStyle = 'DropDownList'; $filterSeverity.Location = '70,4'; $filterSeverity.Width = 90
    [void]$filterSeverity.Items.AddRange(@('All') + $Vocabulary.Severity); $filterSeverity.SelectedIndex = 0
    $filterStatus = New-Object System.Windows.Forms.ComboBox
    $filterStatus.DropDownStyle = 'DropDownList'; $filterStatus.Location = '225,4'; $filterStatus.Width = 130
    [void]$filterStatus.Items.AddRange(@('All') + $Vocabulary.Status); $filterStatus.SelectedIndex = 0
    $find = New-Object System.Windows.Forms.TextBox
    $find.Location = '410,4'; $find.Width = 200
    $filterRow.Controls.AddRange(@(
        (& $newLabel 'Severity:' '12,7'), $filterSeverity, (& $newLabel 'Status:' '175,7'), $filterStatus,
        (& $newLabel 'Find:' '370,7'), $find
    ))

    # --- Grid ---
    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'
    $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false; $grid.RowHeadersVisible = $false
    $grid.SelectionMode = 'FullRowSelect'; $grid.AutoSizeColumnsMode = 'Fill'
    foreach ($col in 'Host','StigId','Severity','Status','Title','Exception') {
        [void]$grid.Columns.Add($col, $col)
    }

    # --- Export ---
    $exportRow = & $newRow 34
    $format = New-Object System.Windows.Forms.ComboBox
    $format.DropDownStyle = 'DropDownList'; $format.Location = '12,6'; $format.Width = 90
    [void]$format.Items.AddRange($Vocabulary.Format)
    if ($format.Items.Count -gt 0) { $format.SelectedIndex = 0 }
    $export = & $newButton 'Export...' '110,4' 90
    $export.Enabled = $false
    $remediate = & $newButton 'Remediate...' '210,4' 100
    $remediate.Enabled = $false
    $countLabel = & $newLabel '0 rules' '320,8'
    $exportRow.Controls.AddRange(@($format, $export, $remediate, $countLabel))

    $rows = @($inputs, $toggleRow, $advancedGroup, $progressRow, $filterRow, $grid, $exportRow)
    $layout.RowCount = $rows.Count
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $style = if ($rows[$i] -eq $grid) {
            New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)
        } else {
            New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)
        }
        [void]$layout.RowStyles.Add($style)
        $layout.Controls.Add($rows[$i], 0, $i)
    }
    $page.Controls.Add($layout)

    @{
        TabPage = $page
        Benchmark = $benchmark; Xccdf = $xccdf; XccdfBrowse = $xccdfBrowse; Targets = $targets
        Profiles = $profiles; ProfileAdd = $profileAdd; ProfileRemove = $profileRemove
        ProfileUp = $profileUp; ProfileDown = $profileDown
        UseCred = $useCred; Run = $run
        AdvancedToggle = $advancedToggle; AdvancedGroup = $advancedGroup
        ContentPath = $contentPath; ContentBrowse = $contentBrowse; ContentPathDefault = $contentPathDefault
        ThrottleLimit = $throttle; JsonPath = $jsonPath; JsonBrowse = $jsonBrowse
        Progress = $progress; Status = $status
        FilterSeverity = $filterSeverity; FilterStatus = $filterStatus; Find = $find
        Grid = $grid; Format = $format; Export = $export; Remediate = $remediate; Count = $countLabel
    }
}

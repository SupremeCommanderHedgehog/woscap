function New-WoscapMainForm {
    <#
        Builds and wires the woscap main window and returns it WITHOUT showing it
        (Show-WoscapGui calls .ShowDialog()). Pure presentation: every action calls a
        cmdlet or a helper. Key controls + the full result set are exposed via $form.Tag
        (a hashtable) for both the handlers and the smoke tests.
    #>
    [CmdletBinding()]
    [OutputType([System.Windows.Forms.Form])]
    param()

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'woscap - STIG scanner'
    $form.Size = New-Object System.Drawing.Size(900, 640)
    $form.MinimumSize = New-Object System.Drawing.Size(760, 520)
    $form.StartPosition = 'CenterScreen'

    # Dropdown vocabularies are DERIVED from their canonical owners (engine ValidateSets /
    # status map) so they can never drift from what the engine emits or accepts (#47).
    $vocab = Get-WoscapGuiVocabulary

    # --- Input row: benchmark + XCCDF ---
    $benchmarkLabel = New-Object System.Windows.Forms.Label
    $benchmarkLabel.Text = 'Benchmark:'; $benchmarkLabel.Location = '12,15'; $benchmarkLabel.AutoSize = $true
    $benchmark = New-Object System.Windows.Forms.ComboBox
    $benchmark.DropDownStyle = 'DropDownList'; $benchmark.Location = '90,12'; $benchmark.Width = 140
    $contentRoot = Join-Path $script:WoscapModuleRoot 'Content'
    if (Test-Path -LiteralPath $contentRoot) {
        foreach ($d in (Get-ChildItem -LiteralPath $contentRoot -Directory | Sort-Object Name)) {
            [void]$benchmark.Items.Add($d.Name)
        }
    }
    if ($benchmark.Items.Count -gt 0) { $benchmark.SelectedIndex = 0 }

    $xccdfLabel = New-Object System.Windows.Forms.Label
    $xccdfLabel.Text = 'XCCDF:'; $xccdfLabel.Location = '250,15'; $xccdfLabel.AutoSize = $true
    $xccdf = New-Object System.Windows.Forms.TextBox
    $xccdf.Location = '300,12'; $xccdf.Width = 420; $xccdf.ReadOnly = $true
    $xccdfBrowse = New-Object System.Windows.Forms.Button
    $xccdfBrowse.Text = 'Browse...'; $xccdfBrowse.Location = '730,10'; $xccdfBrowse.Width = 80

    # --- Input row: targets + profile ---
    $targetsLabel = New-Object System.Windows.Forms.Label
    $targetsLabel.Text = 'Targets:'; $targetsLabel.Location = '12,48'; $targetsLabel.AutoSize = $true
    $targets = New-Object System.Windows.Forms.TextBox
    $targets.Location = '90,45'; $targets.Width = 140; $targets.Text = ''

    $profileLabel = New-Object System.Windows.Forms.Label
    $profileLabel.Text = 'Profile:'; $profileLabel.Location = '250,48'; $profileLabel.AutoSize = $true
    $profile = New-Object System.Windows.Forms.TextBox
    $profile.Location = '300,45'; $profile.Width = 420; $profile.ReadOnly = $true
    $profileBrowse = New-Object System.Windows.Forms.Button
    $profileBrowse.Text = 'Browse...'; $profileBrowse.Location = '730,43'; $profileBrowse.Width = 80

    # --- Credential + Run ---
    $useCred = New-Object System.Windows.Forms.CheckBox
    $useCred.Text = 'Use alternate credential'; $useCred.Location = '90,78'; $useCred.AutoSize = $true
    $run = New-Object System.Windows.Forms.Button
    $run.Text = 'Run'; $run.Location = '730,74'; $run.Width = 80

    # --- Progress ---
    $progress = New-Object System.Windows.Forms.ProgressBar
    $progress.Location = '12,108'; $progress.Width = 620; $progress.Style = 'Continuous'
    $status = New-Object System.Windows.Forms.Label
    $status.Text = ''; $status.Location = '640,110'; $status.AutoSize = $true
    # Non-modal channel for partial-scan warning detail (see the OnWarning handler).
    $statusTip = New-Object System.Windows.Forms.ToolTip

    # --- Filter row ---
    $filterSeverityLabel = New-Object System.Windows.Forms.Label
    $filterSeverityLabel.Text = 'Severity:'; $filterSeverityLabel.Location = '12,142'; $filterSeverityLabel.AutoSize = $true
    $filterSeverity = New-Object System.Windows.Forms.ComboBox
    $filterSeverity.DropDownStyle = 'DropDownList'; $filterSeverity.Location = '70,139'; $filterSeverity.Width = 90
    [void]$filterSeverity.Items.AddRange(@('All') + $vocab.Severity); $filterSeverity.SelectedIndex = 0

    $filterStatusLabel = New-Object System.Windows.Forms.Label
    $filterStatusLabel.Text = 'Status:'; $filterStatusLabel.Location = '175,142'; $filterStatusLabel.AutoSize = $true
    $filterStatus = New-Object System.Windows.Forms.ComboBox
    $filterStatus.DropDownStyle = 'DropDownList'; $filterStatus.Location = '225,139'; $filterStatus.Width = 130
    [void]$filterStatus.Items.AddRange(@('All') + $vocab.Status); $filterStatus.SelectedIndex = 0

    $findLabel = New-Object System.Windows.Forms.Label
    $findLabel.Text = 'Find:'; $findLabel.Location = '370,142'; $findLabel.AutoSize = $true
    $find = New-Object System.Windows.Forms.TextBox
    $find.Location = '410,139'; $find.Width = 200

    # --- Results grid ---
    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Location = '12,170'; $grid.Size = New-Object System.Drawing.Size(860, 380)
    $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false; $grid.RowHeadersVisible = $false
    $grid.SelectionMode = 'FullRowSelect'; $grid.AutoSizeColumnsMode = 'Fill'
    foreach ($col in 'Host','StigId','Severity','Status','Title','Exception') {
        [void]$grid.Columns.Add($col, $col)
    }

    # --- Export row ---
    $format = New-Object System.Windows.Forms.ComboBox
    $format.DropDownStyle = 'DropDownList'; $format.Location = '12,562'; $format.Width = 90
    [void]$format.Items.AddRange($vocab.Format)
    if ($format.Items.Count -gt 0) { $format.SelectedIndex = 0 }   # derived list is never empty in practice; guard the edge
    $export = New-Object System.Windows.Forms.Button
    $export.Text = 'Export...'; $export.Location = '110,560'; $export.Width = 90; $export.Enabled = $false
    $countLabel = New-Object System.Windows.Forms.Label
    $countLabel.Text = '0 rules'; $countLabel.Location = '220,564'; $countLabel.AutoSize = $true

    $form.Controls.AddRange(@(
        $benchmarkLabel, $benchmark, $xccdfLabel, $xccdf, $xccdfBrowse,
        $targetsLabel, $targets, $profileLabel, $profile, $profileBrowse,
        $useCred, $run, $progress, $status,
        $filterSeverityLabel, $filterSeverity, $filterStatusLabel, $filterStatus, $findLabel, $find,
        $grid, $format, $export, $countLabel
    ))

    # Anchoring makes the absolute-positioned layout resize with the window. The grid
    # anchors to all four edges so it grows in both directions; the wide input fields and
    # the progress bar stretch horizontally; the browse/run buttons and status label ride
    # the right edge; the export row stays pinned to the bottom-left as the grid grows down.
    $xccdf.Anchor         = 'Top, Left, Right'
    $profile.Anchor       = 'Top, Left, Right'
    $progress.Anchor      = 'Top, Left, Right'
    $xccdfBrowse.Anchor   = 'Top, Right'
    $profileBrowse.Anchor = 'Top, Right'
    $run.Anchor           = 'Top, Right'
    $status.Anchor        = 'Top, Right'
    $grid.Anchor          = 'Top, Bottom, Left, Right'
    $format.Anchor        = 'Bottom, Left'
    $export.Anchor        = 'Bottom, Left'
    $countLabel.Anchor    = 'Bottom, Left'

    # Full (unfiltered) result set + control refs, exposed for handlers and tests.
    $form.Tag = @{
        Benchmark = $benchmark; Xccdf = $xccdf; Targets = $targets; Profile = $profile
        UseCred = $useCred; Run = $run; Progress = $progress; Status = $status; StatusTip = $statusTip; Grid = $grid
        FilterSeverity = $filterSeverity; FilterStatus = $filterStatus; Find = $find
        Format = $format; Export = $export; Count = $countLabel
        Results = [System.Collections.Generic.List[object]]::new()
    }
    $tag = $form.Tag

    # Single-window: the current form's controls, for the plain event scriptblocks below.
    $script:WoscapGuiTag = $tag

    # Event handlers are PLAIN scriptblocks (no .GetNewClosure()): a plain scriptblock
    # keeps the module's session state, so it resolves the named handler functions and
    # $script:WoscapGuiTag on the WinForms event path. They delegate all logic to the
    # named functions in WoscapGuiHandlers.ps1.
    $xccdfBrowse.Add_Click({
        $t = $script:WoscapGuiTag
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = 'XCCDF (*.xml)|*.xml|All files|*.*'
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $t['Xccdf'].Text = $dlg.FileName }
    })
    $profileBrowse.Add_Click({
        $t = $script:WoscapGuiTag
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = 'Profile (*.psd1)|*.psd1|All files|*.*'
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $t['Profile'].Text = $dlg.FileName }
    })

    $filterSeverity.Add_SelectedIndexChanged({ Update-WoscapGuiView -Tag $script:WoscapGuiTag })
    $filterStatus.Add_SelectedIndexChanged({ Update-WoscapGuiView -Tag $script:WoscapGuiTag })
    $find.Add_TextChanged({ Update-WoscapGuiView -Tag $script:WoscapGuiTag })

    $run.Add_Click({ Invoke-WoscapGuiRun -Tag $script:WoscapGuiTag })
    $export.Add_Click({ Invoke-WoscapGuiExport -Tag $script:WoscapGuiTag })

    # Release the module-scoped reference when the window closes, so the form and the
    # full result set do not stay reachable for the rest of the PowerShell session.
    $form.Add_FormClosed({ $script:WoscapGuiTag = $null })

    $form
}

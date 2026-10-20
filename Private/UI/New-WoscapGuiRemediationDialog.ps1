function New-WoscapGuiRemediationDialog {
    <#
        Builds (does not show) the modal confirmation dialog for a remediation preview.
        One row per planned action, ticked by default; Manual rows are locked unticked.
        Apply is never the AcceptButton, so Enter cannot apply. Controls are exposed on
        $form.Tag for helpers and tests.
    #>
    [CmdletBinding()]
    [OutputType([System.Windows.Forms.Form])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Plan,
        [string] $Summary = '',
        [Parameter(Mandatory)] [bool] $Elevated
    )
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Confirm remediation'
    $form.Size = New-Object System.Drawing.Size(760, 460)
    $form.MinimumSize = New-Object System.Drawing.Size(600, 360)
    $form.StartPosition = 'CenterParent'
    $form.ShowInTaskbar = $false

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'; $layout.ColumnCount = 1; $layout.RowCount = 3
    # Pin the column to the form width; without it a long header widens the column and pushes the buttons off-screen.
    [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))

    $auto   = @($Plan | Where-Object { [string](Get-WoscapObjectProperty $_ 'State' '') -eq 'Planned' }).Count
    $manual = @($Plan).Count - $auto
    $header = New-Object System.Windows.Forms.Label
    $header.Dock = 'Fill'; $header.AutoSize = $true
    $header.Padding = New-Object System.Windows.Forms.Padding(6)
    $header.Text = "$auto fixes will change this computer. $manual require manual action."
    if ($Summary) { $header.Text += " $Summary" }

    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'
    $grid.AllowUserToAddRows = $false; $grid.AllowUserToDeleteRows = $false
    $grid.RowHeadersVisible = $false; $grid.AutoSizeColumnsMode = 'Fill'; $grid.SelectionMode = 'FullRowSelect'
    $check = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
    $check.HeaderText = 'Apply'; $check.FillWeight = 20
    [void]$grid.Columns.Add($check)
    foreach ($col in 'STIG IDs', 'Title', 'Change', 'Kind') {
        $i = $grid.Columns.Add($col, $col)
        $grid.Columns[$i].ReadOnly = $true
    }
    foreach ($p in @($Plan)) {
        $isAuto = [string](Get-WoscapObjectProperty $p 'State' '') -eq 'Planned'
        $kind = if ($isAuto) { 'Automatic' } else { 'Manual: ' + [string](Get-WoscapObjectProperty $p 'Detail' '') }
        $ids = @(Get-WoscapObjectProperty $p 'StigIds' @()) -join ', '
        $idx = $grid.Rows.Add($isAuto, $ids, [string](Get-WoscapObjectProperty $p 'Title' ''),
            [string](Get-WoscapObjectProperty $p 'Action' ''), $kind)
        $row = $grid.Rows[$idx]
        $row.Tag = $p
        if (-not $isAuto) {
            $row.Cells[0].ReadOnly = $true
            $row.DefaultCellStyle.ForeColor = [System.Drawing.SystemColors]::GrayText
        }
    }

    # Buttons flow from the right edge; no absolute coordinates to drift when resized.
    $buttons = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttons.Dock = 'Fill'; $buttons.AutoSize = $true; $buttons.FlowDirection = 'RightToLeft'; $buttons.WrapContents = $false
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'; $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $apply = New-Object System.Windows.Forms.Button
    $apply.Text = 'Apply'; $apply.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $note = New-Object System.Windows.Forms.Label
    $note.Text = 'Run woscap as administrator to apply.'; $note.AutoSize = $true
    $note.Margin = New-Object System.Windows.Forms.Padding(3, 8, 3, 3)
    $note.Visible = -not $Elevated
    $buttons.Controls.AddRange(@($cancel, $apply, $note))

    $layout.Controls.Add($header, 0, 0)
    $layout.Controls.Add($grid, 0, 1)
    $layout.Controls.Add($buttons, 0, 2)
    $form.Controls.Add($layout)
    $form.CancelButton = $cancel

    $form.Tag = @{ Grid = $grid; Apply = $apply; Cancel = $cancel; ElevationNote = $note; Header = $header; Elevated = $Elevated }

    # Commit checkbox clicks immediately so CellValueChanged fires on click, not on focus loss.
    $grid.Add_CurrentCellDirtyStateChanged({
        param($s, $e)
        if ($s.IsCurrentCellDirty) { [void]$s.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit) }
    })
    $grid.Add_CellValueChanged({
        param($s, $e)
        $f = $s.FindForm()
        if ($f) { Update-WoscapGuiRemediationApply -Tag $f.Tag }
    })
    Update-WoscapGuiRemediationApply -Tag $form.Tag
    $form
}

function Get-WoscapGuiRemediationSelection {
    <# StigIds of every ticked, non-Manual row, flattened (a merged audit row yields all of its). #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][hashtable] $Tag)
    @(foreach ($row in $Tag['Grid'].Rows) {
        if ($row.Cells[0].Value -eq $true -and -not $row.Cells[0].ReadOnly) {
            @(Get-WoscapObjectProperty $row.Tag 'StigIds' @())
        }
    })
}

function Update-WoscapGuiRemediationApply {
    <# Apply needs elevation and at least one ticked automatic fix. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $Tag['Apply'].Enabled = [bool]$Tag['Elevated'] -and @(Get-WoscapGuiRemediationSelection -Tag $Tag).Count -gt 0
}

function Show-WoscapGuiRemediationDialog {
    <# Seam: shows the confirmation dialog; returns ticked StigIds, or nothing on cancel. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Plan,
        [string] $Summary = '',
        [Parameter(Mandatory)] [bool] $Elevated
    )
    $d = New-WoscapGuiRemediationDialog -Plan $Plan -Summary $Summary -Elevated $Elevated
    try {
        if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Get-WoscapGuiRemediationSelection -Tag $d.Tag }
    } finally { $d.Dispose() }
}

function New-WoscapGuiRemediationReport {
    <# Builds (does not show) the post-apply report: per-fix State/After plus counts. #>
    [CmdletBinding()]
    [OutputType([System.Windows.Forms.Form])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Result
    )
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Remediation report'
    $form.Size = New-Object System.Drawing.Size(760, 460)
    $form.MinimumSize = New-Object System.Drawing.Size(600, 360)
    $form.StartPosition = 'CenterParent'
    $form.ShowInTaskbar = $false

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'; $layout.ColumnCount = 1; $layout.RowCount = 3
    # Pin the column to the form width; without it a long header widens the column and pushes the buttons off-screen.
    [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)))

    $count = { param($s) @($Result | Where-Object { [string](Get-WoscapObjectProperty $_ 'State' '') -eq $s }).Count }
    $summary = New-Object System.Windows.Forms.Label
    $summary.Dock = 'Fill'; $summary.AutoSize = $true
    $summary.Padding = New-Object System.Windows.Forms.Padding(6)
    $summary.Text = 'Applied: {0}   Failed: {1}   Manual: {2}' -f (& $count 'Applied'), (& $count 'Failed'), (& $count 'Manual')

    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'; $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false; $grid.RowHeadersVisible = $false
    $grid.AutoSizeColumnsMode = 'Fill'; $grid.SelectionMode = 'FullRowSelect'
    foreach ($col in 'STIG IDs', 'Title', 'Change', 'State', 'After', 'Detail') { [void]$grid.Columns.Add($col, $col) }
    foreach ($r in @($Result)) {
        $idx = $grid.Rows.Add((@(Get-WoscapObjectProperty $r 'StigIds' @()) -join ', '),
            [string](Get-WoscapObjectProperty $r 'Title' ''), [string](Get-WoscapObjectProperty $r 'Action' ''),
            [string](Get-WoscapObjectProperty $r 'State' ''), [string](Get-WoscapObjectProperty $r 'After' ''),
            [string](Get-WoscapObjectProperty $r 'Detail' ''))
        $grid.Rows[$idx].Tag = $r
    }

    $buttons = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttons.Dock = 'Fill'; $buttons.AutoSize = $true; $buttons.FlowDirection = 'RightToLeft'; $buttons.WrapContents = $false
    $close = New-Object System.Windows.Forms.Button
    $close.Text = 'Close'; $close.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $rescan = New-Object System.Windows.Forms.Button
    $rescan.Text = 'Re-scan'; $rescan.DialogResult = [System.Windows.Forms.DialogResult]::Retry
    $buttons.Controls.AddRange(@($close, $rescan))

    $layout.Controls.Add($summary, 0, 0)
    $layout.Controls.Add($grid, 0, 1)
    $layout.Controls.Add($buttons, 0, 2)
    $form.Controls.Add($layout)
    $form.CancelButton = $close
    $form.Tag = @{ Grid = $grid; Summary = $summary; Rescan = $rescan; Close = $close }
    $form
}

function Show-WoscapGuiRemediationReport {
    <# Seam: shows the report; returns 'Rescan' or 'Close'. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Result)
    $d = New-WoscapGuiRemediationReport -Result $Result
    try {
        if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::Retry) { 'Rescan' } else { 'Close' }
    } finally { $d.Dispose() }
}

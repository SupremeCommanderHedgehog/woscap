function New-WoscapGuiContentFrame {
    <#
        Shared shell for the content dialogs: a sized modal form holding a TableLayoutPanel
        whose last column is Percent 100, so long text cannot push the buttons off-screen.
        Two columns gives a label column (AutoSize) plus a stretching field column.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Title,
        [Parameter(Mandatory)][int[]] $Size,
        [Parameter(Mandatory)][int[]] $MinimumSize,
        [ValidateRange(1, 2)][int] $Columns = 1
    )
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Size = New-Object System.Drawing.Size($Size[0], $Size[1])
    $form.MinimumSize = New-Object System.Drawing.Size($MinimumSize[0], $MinimumSize[1])
    $form.StartPosition = 'CenterParent'
    $form.ShowInTaskbar = $false
    $form.MinimizeBox = $false; $form.MaximizeBox = $false

    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = 'Fill'; $layout.ColumnCount = $Columns
    $layout.Padding = New-Object System.Windows.Forms.Padding(6)
    if ($Columns -eq 2) {
        [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    }
    [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $form.Controls.Add($layout)
    @{ Form = $form; Layout = $layout }
}

function Add-WoscapGuiContentRow {
    <# Appends one row to a content-dialog layout; -Fill makes it the row that absorbs spare height. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Layout,
        [Parameter(Mandatory)] $Control,
        $Label,
        [switch] $Fill
    )
    $row = $Layout.RowCount
    $Layout.RowCount = $row + 1
    $style = if ($Fill) {
        New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)
    } else {
        New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize)
    }
    [void]$Layout.RowStyles.Add($style)
    if ($Label) {
        $l = New-Object System.Windows.Forms.Label
        $l.Text = $Label; $l.AutoSize = $true; $l.Anchor = 'Left'
        $Layout.Controls.Add($l, 0, $row)
        $Layout.Controls.Add($Control, 1, $row)
    } else {
        $Layout.Controls.Add($Control, 0, $row)
        if ($Layout.ColumnCount -gt 1) { $Layout.SetColumnSpan($Control, $Layout.ColumnCount) }
    }
}

function New-WoscapGuiContentButtons {
    <#
        Right-aligned button strip. Cancel is the CancelButton; the action button is never the
        AcceptButton, so Enter cannot download, update, remove or accept terms.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Form,
        [Parameter(Mandatory)][string] $ActionText,
        [System.Windows.Forms.DialogResult] $ActionResult = [System.Windows.Forms.DialogResult]::OK,
        [string] $CancelText = 'Cancel'
    )
    $panel = New-Object System.Windows.Forms.FlowLayoutPanel
    $panel.Dock = 'Fill'; $panel.AutoSize = $true; $panel.FlowDirection = 'RightToLeft'; $panel.WrapContents = $false
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = $CancelText; $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $cancel.AutoSize = $true
    $action = New-Object System.Windows.Forms.Button
    $action.Text = $ActionText; $action.DialogResult = $ActionResult; $action.AutoSize = $true
    $panel.Controls.AddRange(@($cancel, $action))
    $Form.CancelButton = $cancel
    @{ Panel = $panel; Action = $action; Cancel = $cancel }
}

function New-WoscapGuiReadOnlyField {
    <# Read-only, selectable single-line text that stretches with the column (long paths stay readable). #>
    [CmdletBinding()]
    param([AllowEmptyString()][string] $Text = '')
    $t = New-Object System.Windows.Forms.TextBox
    $t.ReadOnly = $true; $t.Text = $Text; $t.Anchor = 'Left, Right'
    $t
}

function New-WoscapGuiDownloadDialog {
    <#
        Builds (does not show) the Download dialog. Download validates the name before
        closing (Confirm-WoscapGuiDownloadDialog); an unsafe name shows a message and keeps
        the dialog open.
    #>
    [CmdletBinding()]
    [OutputType([System.Windows.Forms.Form])]
    param()
    $f = New-WoscapGuiContentFrame -Title 'Download STIG content' -Size 600, 280 -MinimumSize 460, 260 -Columns 2
    $form = $f.Form; $layout = $f.Layout

    $combo = New-Object System.Windows.Forms.ComboBox
    $combo.DropDownStyle = 'DropDown'; $combo.Anchor = 'Left, Right'
    foreach ($k in @((Get-WoscapStigManifest).Keys | Sort-Object)) { [void]$combo.Items.Add([string]$k) }
    $url = New-Object System.Windows.Forms.TextBox
    $url.Anchor = 'Left, Right'
    $scrape = New-Object System.Windows.Forms.CheckBox
    $scrape.Text = 'Look up the newest revision on the DISA page'; $scrape.AutoSize = $true
    $force = New-Object System.Windows.Forms.CheckBox
    $force.Text = 'Re-download even if cached'; $force.AutoSize = $true
    $spacer = New-Object System.Windows.Forms.Panel
    $spacer.Dock = 'Fill'; $spacer.Height = 0
    $b = New-WoscapGuiContentButtons -Form $form -ActionText 'Download' -ActionResult ([System.Windows.Forms.DialogResult]::None)

    Add-WoscapGuiContentRow -Layout $layout -Label 'Benchmark:' -Control $combo
    Add-WoscapGuiContentRow -Layout $layout -Label 'URL (optional):' -Control $url
    Add-WoscapGuiContentRow -Layout $layout -Control $scrape
    Add-WoscapGuiContentRow -Layout $layout -Control $force
    Add-WoscapGuiContentRow -Layout $layout -Control $spacer -Fill
    Add-WoscapGuiContentRow -Layout $layout -Control $b.Panel

    $form.Tag = @{ Benchmark = $combo; Url = $url; AllowScrape = $scrape; Force = $force; Download = $b.Action; Cancel = $b.Cancel }
    $b.Action.Add_Click({
        param($s, $e)
        $owner = $s.FindForm()
        if ($owner) { [void](Confirm-WoscapGuiDownloadDialog -Form $owner) }
    })
    $form
}

function Get-WoscapGuiDownloadRequest {
    <# The dialog's choices, trimmed; throws on an unsafe benchmark name so it can never reach Save. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $name = ([string]$Tag['Benchmark'].Text).Trim()
    Assert-WoscapSafePathSegment -Segment $name -Kind 'benchmark name'
    @{
        Benchmark   = $name
        Url         = ([string]$Tag['Url'].Text).Trim()
        AllowScrape = [bool]$Tag['AllowScrape'].Checked
        Force       = [bool]$Tag['Force'].Checked
    }
}

function Confirm-WoscapGuiDownloadDialog {
    <# Download click: closes with OK on a safe name, otherwise shows why and keeps the dialog open. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][System.Windows.Forms.Form] $Form)
    try {
        [void](Get-WoscapGuiDownloadRequest -Tag $Form.Tag)
    } catch {
        Show-WoscapGuiMessage -Text $_.Exception.Message -Caption 'Download STIG content'
        return $false
    }
    $Form.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $true
}

function Show-WoscapGuiDownloadDialog {
    <# Seam: $null on cancel, else @{ Benchmark; Url; AllowScrape; Force } (trimmed, validated). #>
    [CmdletBinding()]
    param()
    $d = New-WoscapGuiDownloadDialog
    try {
        if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return Get-WoscapGuiDownloadRequest -Tag $d.Tag }
        $null
    } finally { $d.Dispose() }
}

function New-WoscapGuiUpdateDialog {
    <#
        Builds (does not show) the Update options dialog. A blank -Benchmark means every
        cached benchmark; the URL only applies (and is only enabled) for a single benchmark.
    #>
    [CmdletBinding()]
    [OutputType([System.Windows.Forms.Form])]
    param([AllowEmptyString()][string] $Benchmark = '')
    $single = -not [string]::IsNullOrWhiteSpace($Benchmark)
    $f = New-WoscapGuiContentFrame -Title 'Update cached STIG content' -Size 600, 260 -MinimumSize 460, 240 -Columns 2
    $form = $f.Form; $layout = $f.Layout

    $header = New-Object System.Windows.Forms.Label
    $header.Dock = 'Fill'; $header.AutoSize = $true
    $header.Text = if ($single) { "Update $($Benchmark.Trim()) from DISA. The next step previews what will change." }
        else { 'Update every cached benchmark from DISA. The next step previews what will change.' }
    $url = New-Object System.Windows.Forms.TextBox
    $url.Anchor = 'Left, Right'; $url.Enabled = $single
    $scrape = New-Object System.Windows.Forms.CheckBox
    $scrape.Text = 'Look up the newest revision on the DISA page'; $scrape.AutoSize = $true
    $note = New-Object System.Windows.Forms.Label
    $note.Dock = 'Fill'; $note.AutoSize = $true
    $note.Text = if ($single) { '' } else { 'A URL can only be given when updating a single benchmark.' }
    $note.Visible = -not $single
    $b = New-WoscapGuiContentButtons -Form $form -ActionText 'Preview...'

    Add-WoscapGuiContentRow -Layout $layout -Control $header
    Add-WoscapGuiContentRow -Layout $layout -Label 'URL (optional):' -Control $url
    Add-WoscapGuiContentRow -Layout $layout -Control $scrape
    Add-WoscapGuiContentRow -Layout $layout -Control $note -Fill
    Add-WoscapGuiContentRow -Layout $layout -Control $b.Panel

    $form.Tag = @{ Header = $header; Url = $url; AllowScrape = $scrape; Note = $note; Single = $single
        Preview = $b.Action; Cancel = $b.Cancel }
    $form
}

function Get-WoscapGuiUpdateOptions {
    <# @{ Url; AllowScrape }; Url is always '' when updating every benchmark. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $u = if ($Tag['Single']) { ([string]$Tag['Url'].Text).Trim() } else { '' }
    @{ Url = $u; AllowScrape = [bool]$Tag['AllowScrape'].Checked }
}

function Show-WoscapGuiUpdateDialog {
    <# Seam: $null on cancel, else @{ Url; AllowScrape }. #>
    [CmdletBinding()]
    param([AllowEmptyString()][string] $Benchmark = '')
    $d = New-WoscapGuiUpdateDialog -Benchmark $Benchmark
    try {
        if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return Get-WoscapGuiUpdateOptions -Tag $d.Tag }
        $null
    } finally { $d.Dispose() }
}

function New-WoscapGuiContentGrid {
    <# Read-only grid with the given columns; each row's Tag is its source object. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]] $Header,
        [Parameter(Mandatory)][string[]] $Property,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Rows
    )
    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'; $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false; $grid.AllowUserToDeleteRows = $false
    $grid.RowHeadersVisible = $false; $grid.AutoSizeColumnsMode = 'Fill'; $grid.SelectionMode = 'FullRowSelect'
    foreach ($h in $Header) { [void]$grid.Columns.Add($h, $h) }
    foreach ($r in @($Rows)) {
        $values = foreach ($p in $Property) { [string](Get-WoscapObjectProperty $r $p '') }
        $idx = $grid.Rows.Add([object[]]@($values))
        $grid.Rows[$idx].Tag = $r
    }
    $grid
}

function New-WoscapGuiUpdateConfirmDialog {
    <# Builds (does not show) the confirmation listing exactly the -WhatIf rows; Update is not the AcceptButton. #>
    [CmdletBinding()]
    [OutputType([System.Windows.Forms.Form])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Rows)
    $f = New-WoscapGuiContentFrame -Title 'Confirm update' -Size 640, 400 -MinimumSize 480, 300
    $form = $f.Form; $layout = $f.Layout

    $count = @($Rows).Count
    $header = New-Object System.Windows.Forms.Label
    $header.Dock = 'Fill'; $header.AutoSize = $true
    $header.Text = "$count benchmarks will be downloaded again from DISA and replaced in the cache if a newer revision exists."
    $grid = New-WoscapGuiContentGrid -Header 'Benchmark', 'Current revision' -Property 'Benchmark', 'FromRevision' -Rows $Rows
    $b = New-WoscapGuiContentButtons -Form $form -ActionText 'Update'

    Add-WoscapGuiContentRow -Layout $layout -Control $header
    Add-WoscapGuiContentRow -Layout $layout -Control $grid -Fill
    Add-WoscapGuiContentRow -Layout $layout -Control $b.Panel
    $form.Tag = @{ Header = $header; Grid = $grid; Update = $b.Action; Cancel = $b.Cancel }
    $form
}

function Show-WoscapGuiUpdateConfirmDialog {
    <# Seam: $true only when the operator clicked Update. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Rows)
    $d = New-WoscapGuiUpdateConfirmDialog -Rows $Rows
    try { $d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK } finally { $d.Dispose() }
}

function New-WoscapGuiUpdateReport {
    <# Builds (does not show) the post-update report: Benchmark/Status/From/To/Reason plus counts. #>
    [CmdletBinding()]
    [OutputType([System.Windows.Forms.Form])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Result)
    $f = New-WoscapGuiContentFrame -Title 'Update report' -Size 760, 420 -MinimumSize 560, 320
    $form = $f.Form; $layout = $f.Layout

    $count = { param($s) @($Result | Where-Object { [string](Get-WoscapObjectProperty $_ 'Status' '') -eq $s }).Count }
    $summary = New-Object System.Windows.Forms.Label
    $summary.Dock = 'Fill'; $summary.AutoSize = $true
    $summary.Text = 'Updated: {0}   Already current: {1}   Failed: {2}' -f (& $count 'Updated'), (& $count 'AlreadyCurrent'), (& $count 'Failed')
    $grid = New-WoscapGuiContentGrid -Header 'Benchmark', 'Status', 'From', 'To', 'Reason' `
        -Property 'Benchmark', 'Status', 'FromRevision', 'ToRevision', 'Reason' -Rows $Result

    $panel = New-Object System.Windows.Forms.FlowLayoutPanel
    $panel.Dock = 'Fill'; $panel.AutoSize = $true; $panel.FlowDirection = 'RightToLeft'; $panel.WrapContents = $false
    $close = New-Object System.Windows.Forms.Button
    $close.Text = 'Close'; $close.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $panel.Controls.Add($close)
    $form.CancelButton = $close

    Add-WoscapGuiContentRow -Layout $layout -Control $summary
    Add-WoscapGuiContentRow -Layout $layout -Control $grid -Fill
    Add-WoscapGuiContentRow -Layout $layout -Control $panel
    $form.Tag = @{ Summary = $summary; Grid = $grid; Close = $close }
    $form
}

function Show-WoscapGuiUpdateReport {
    <# Seam: shows the update report until closed. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Result)
    $d = New-WoscapGuiUpdateReport -Result $Result
    try { [void]$d.ShowDialog() } finally { $d.Dispose() }
}

function New-WoscapGuiRemoveDialog {
    <# Builds (does not show) the Remove dialog; "This revision only" is the default and Remove is not the AcceptButton. #>
    [CmdletBinding()]
    [OutputType([System.Windows.Forms.Form])]
    param(
        [Parameter(Mandatory)][string] $Benchmark,
        [Parameter(Mandatory)][AllowEmptyString()][string] $Revision,
        [Parameter(Mandatory)][AllowEmptyString()][string] $CacheRoot
    )
    $f = New-WoscapGuiContentFrame -Title 'Remove cached STIG content' -Size 600, 300 -MinimumSize 460, 280 -Columns 2
    $form = $f.Form; $layout = $f.Layout

    $bench = New-WoscapGuiReadOnlyField -Text $Benchmark
    $rev = New-WoscapGuiReadOnlyField -Text $Revision
    $root = New-WoscapGuiReadOnlyField -Text $CacheRoot
    # Fixed-height, ellipsized radios: an AutoSize radio with a long name would widen past the column.
    $one = New-Object System.Windows.Forms.RadioButton
    $one.Text = 'This revision only'; $one.Checked = $true
    $one.AutoSize = $false; $one.Dock = 'Fill'; $one.AutoEllipsis = $true
    $all = New-Object System.Windows.Forms.RadioButton
    $all.Text = "All revisions of $Benchmark"
    $all.AutoSize = $false; $all.Dock = 'Fill'; $all.AutoEllipsis = $true
    $spacer = New-Object System.Windows.Forms.Panel
    $spacer.Dock = 'Fill'; $spacer.Height = 0
    $b = New-WoscapGuiContentButtons -Form $form -ActionText 'Remove'

    Add-WoscapGuiContentRow -Layout $layout -Label 'Benchmark:' -Control $bench
    Add-WoscapGuiContentRow -Layout $layout -Label 'Revision:' -Control $rev
    Add-WoscapGuiContentRow -Layout $layout -Label 'Cache folder:' -Control $root
    Add-WoscapGuiContentRow -Layout $layout -Control $one
    Add-WoscapGuiContentRow -Layout $layout -Control $all
    Add-WoscapGuiContentRow -Layout $layout -Control $spacer -Fill
    Add-WoscapGuiContentRow -Layout $layout -Control $b.Panel

    $form.Tag = @{ BenchmarkText = $bench; RevisionText = $rev; CacheRootText = $root
        ThisRevision = $one; AllRevisions = $all; Remove = $b.Action; Cancel = $b.Cancel }
    $form
}

function Get-WoscapGuiRemoveChoice {
    <# @{ AllRevisions = [bool] } from the Remove dialog's radio buttons. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][hashtable] $Tag)
    @{ AllRevisions = [bool]$Tag['AllRevisions'].Checked }
}

function Show-WoscapGuiRemoveDialog {
    <# Seam: $null on cancel, else @{ AllRevisions = [bool] }. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Benchmark,
        [Parameter(Mandatory)][AllowEmptyString()][string] $Revision,
        [Parameter(Mandatory)][AllowEmptyString()][string] $CacheRoot
    )
    $d = New-WoscapGuiRemoveDialog -Benchmark $Benchmark -Revision $Revision -CacheRoot $CacheRoot
    try {
        if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return Get-WoscapGuiRemoveChoice -Tag $d.Tag }
        $null
    } finally { $d.Dispose() }
}

function New-WoscapGuiDisaTermsDialog {
    <# Builds (does not show) the DISA terms dialog; Remember starts unticked and Accept is not the AcceptButton. #>
    [CmdletBinding()]
    [OutputType([System.Windows.Forms.Form])]
    param([Parameter(Mandatory)][string] $Notice)
    $f = New-WoscapGuiContentFrame -Title 'DISA content terms' -Size 620, 340 -MinimumSize 460, 280
    $form = $f.Form; $layout = $f.Layout

    $text = New-Object System.Windows.Forms.TextBox
    $text.Multiline = $true; $text.ReadOnly = $true; $text.WordWrap = $true
    $text.ScrollBars = 'Vertical'; $text.Dock = 'Fill'
    # The notice is a here-string with bare LF line breaks; a TextBox needs CRLF.
    $text.Text = ($Notice -replace '\r?\n', "`r`n").Trim()
    $remember = New-Object System.Windows.Forms.CheckBox
    $remember.Text = 'Remember on this workstation'; $remember.AutoSize = $true; $remember.Checked = $false
    $b = New-WoscapGuiContentButtons -Form $form -ActionText 'Accept'

    Add-WoscapGuiContentRow -Layout $layout -Control $text -Fill
    Add-WoscapGuiContentRow -Layout $layout -Control $remember
    Add-WoscapGuiContentRow -Layout $layout -Control $b.Panel
    $form.Tag = @{ Notice = $text; Remember = $remember; Accept = $b.Action; Cancel = $b.Cancel }
    $form
}

function Get-WoscapGuiDisaTermsChoice {
    <# @{ Remember = [bool] } from the terms dialog. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][hashtable] $Tag)
    @{ Remember = [bool]$Tag['Remember'].Checked }
}

function Show-WoscapGuiDisaTermsDialog {
    <# Seam over the terms dialog: $null on cancel, else @{ Remember = [bool] }. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Notice)
    $d = New-WoscapGuiDisaTermsDialog -Notice $Notice
    try {
        if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return Get-WoscapGuiDisaTermsChoice -Tag $d.Tag }
        $null
    } finally { $d.Dispose() }
}

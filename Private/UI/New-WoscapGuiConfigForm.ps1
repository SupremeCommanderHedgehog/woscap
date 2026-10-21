function New-WoscapGuiConfigForm {
    <#
    .SYNOPSIS
        Builds (does not show) the plugin config form for one hook.
    .DESCRIPTION
        -Options is the schema list from Get-WoscapGuiConfigOptions. One row per option:
        Text/Path text box (+Browse for Path: open file, folder or save-as per the option's PathKind,
        File by default), Number NumericUpDown, Bool check box,
        Credential "Set..." via Get-WoscapGuiCredential (shown only as "(not set)"/"(set)"),
        Secret masked text box, List multi-line text (one item per line), Table Key/Value grid.
        $null -Options means the plugin has no schema: a generic Key/Type/Value grid instead.
        Run validates before closing (Confirm-WoscapGuiConfigForm) and is not the AcceptButton;
        Cancel is the CancelButton. Nothing entered here is persisted.
    .PARAMETER Options
        Schema entries (@{ Name; Type; Required?; Default?; Hooks; Help?; PathKind? }), an empty list
        for a hook with no options, or $null for the generic grid.
    .PARAMETER Title
        Form caption.
    .EXAMPLE
        $f = New-WoscapGuiConfigForm -Options (Get-WoscapGuiConfigOptions -Plugin $p -Hook 'Export-Findings') -Title 'Export findings'
    #>
    [CmdletBinding()]
    [OutputType([System.Windows.Forms.Form])]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]] $Options,
        [Parameter(Mandatory)][string] $Title
    )
    $f = New-WoscapGuiContentFrame -Title $Title -Size 640, 480 -MinimumSize 460, 320
    $form = $f.Form; $layout = $f.Layout
    $tip = New-Object System.Windows.Forms.ToolTip
    $tag = @{ Mode = 'Schema'; Fields = [ordered]@{}; Grid = $null; ToolTip = $tip }

    if ($null -eq $Options) {
        $tag['Mode'] = 'Generic'
        $note = New-Object System.Windows.Forms.Label
        $note.Dock = 'Fill'; $note.AutoSize = $true
        $note.Text = 'This integration declares no options. Add one row per setting. List values are comma-separated; ' +
            'Bool is true or false. Credentials and secrets cannot be entered here.'
        $grid = New-Object System.Windows.Forms.DataGridView
        $grid.Dock = 'Fill'; $grid.AllowUserToAddRows = $true; $grid.RowHeadersVisible = $false
        $grid.AutoSizeColumnsMode = 'Fill'
        [void]$grid.Columns.Add('Key', 'Key')
        $type = New-Object System.Windows.Forms.DataGridViewComboBoxColumn
        $type.Name = 'Type'; $type.HeaderText = 'Type'
        $type.Items.AddRange([object[]]@('Text', 'Number', 'Bool', 'Path', 'List'))
        [void]$grid.Columns.Add($type)
        [void]$grid.Columns.Add('Value', 'Value')
        $tag['Grid'] = $grid
        Add-WoscapGuiContentRow -Layout $layout -Control $note
        Add-WoscapGuiContentRow -Layout $layout -Control $grid -Fill
    } else {
        # Scrolling host: many options must never push the buttons off the form.
        $scroller = New-Object System.Windows.Forms.Panel
        $scroller.Dock = 'Fill'; $scroller.AutoScroll = $true
        $inner = New-Object System.Windows.Forms.TableLayoutPanel
        $inner.Dock = 'Top'; $inner.AutoSize = $true; $inner.AutoSizeMode = 'GrowAndShrink'; $inner.ColumnCount = 2
        [void]$inner.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
        [void]$inner.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
        $scroller.Controls.Add($inner)

        $note = New-Object System.Windows.Forms.Label
        $note.AutoSize = $true; $note.Anchor = 'Left'
        $anyRequired = @($Options | Where-Object { $_ -is [hashtable] -and $_.ContainsKey('Required') -and $_.Required }).Count -gt 0
        $note.Text = if (@($Options).Count -eq 0) { 'This action takes no options.' } elseif ($anyRequired) { '* required' } else { '' }
        $note.Visible = [bool]$note.Text
        Add-WoscapGuiContentRow -Layout $inner -Control $note

        foreach ($o in @($Options)) {
            if ($o -isnot [hashtable]) { continue }
            $name = [string]$o['Name']
            if ([string]::IsNullOrWhiteSpace($name) -or $tag['Fields'].Contains($name)) { continue }
            $field = New-WoscapGuiConfigField -Option $o
            $required = $o.ContainsKey('Required') -and [bool]$o['Required']
            $labelText = if ($required) { "$name *:" } else { "${name}:" }
            Add-WoscapGuiContentRow -Layout $inner -Label $labelText -Control $field['Row']
            # Cap the label column so a long name cannot squeeze the fields off the form.
            $label = $inner.GetControlFromPosition(0, $inner.RowCount - 1)
            $label.MaximumSize = New-Object System.Drawing.Size(200, 0)
            $help = if ($o.ContainsKey('Help') -and $o['Help']) { "$name`r`n$($o['Help'])" } else { $name }
            $tip.SetToolTip($label, $help)
            $tip.SetToolTip($field['Control'], $help)
            $tag['Fields'][$name] = $field
        }
        Add-WoscapGuiContentRow -Layout $layout -Control $scroller -Fill
    }

    $b = New-WoscapGuiContentButtons -Form $form -ActionText 'Run' -ActionResult ([System.Windows.Forms.DialogResult]::None)
    Add-WoscapGuiContentRow -Layout $layout -Control $b.Panel
    $tag['Run'] = $b.Action; $tag['Cancel'] = $b.Cancel
    $form.Tag = $tag
    $b.Action.Add_Click({
        param($s, $e)
        $owner = $s.FindForm()
        if ($owner) { [void](Confirm-WoscapGuiConfigForm -Form $owner) }
    })
    $form.Add_Disposed({
        param($s, $e)
        if ($s.Tag -is [hashtable] -and $s.Tag['ToolTip']) { $s.Tag['ToolTip'].Dispose() }
    })
    $form
}

function New-WoscapGuiConfigField {
    <# One option's input: @{ Option; Row (placed in the layout); Control; Browse; Status; Value }. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][hashtable] $Option)
    $field = @{ Option = $Option; Row = $null; Control = $null; Browse = $null; Status = $null; Value = $null }
    $hasDefault = $Option.ContainsKey('Default') -and $null -ne $Option['Default']
    $default = if ($hasDefault) { $Option['Default'] } else { $null }

    switch ([string]$Option['Type']) {
        'Number' {
            $n = New-Object System.Windows.Forms.NumericUpDown
            $n.Minimum = [int]::MinValue; $n.Maximum = [int]::MaxValue; $n.Anchor = 'Left, Right'
            # Blank text means "not given" so an optional number can be omitted.
            if ($hasDefault) { $n.Value = [decimal][int]$default; $n.Text = [string][int]$default } else { $n.Text = '' }
            $field['Control'] = $n; $field['Row'] = $n
        }
        'Bool' {
            $c = New-Object System.Windows.Forms.CheckBox
            $c.AutoSize = $true; $c.Anchor = 'Left'; $c.Checked = $hasDefault -and [bool]$default
            $field['Control'] = $c; $field['Row'] = $c
        }
        'Credential' {
            $panel = New-Object System.Windows.Forms.FlowLayoutPanel
            $panel.AutoSize = $true; $panel.WrapContents = $false; $panel.Anchor = 'Left'
            $panel.Margin = New-Object System.Windows.Forms.Padding(0)
            $set = New-Object System.Windows.Forms.Button
            $set.Text = 'Set...'; $set.AutoSize = $true; $set.Tag = $field
            $status = New-Object System.Windows.Forms.Label
            $status.Text = '(not set)'; $status.AutoSize = $true; $status.Anchor = 'Left'
            $panel.Controls.AddRange(@($set, $status))
            $set.Add_Click({ param($s, $e) Invoke-WoscapGuiConfigCredential -Field $s.Tag })
            $field['Control'] = $set; $field['Status'] = $status; $field['Row'] = $panel
        }
        'List' {
            $t = New-Object System.Windows.Forms.TextBox
            $t.Multiline = $true; $t.AcceptsReturn = $true; $t.ScrollBars = 'Vertical'; $t.WordWrap = $false
            $t.Height = 64; $t.Anchor = 'Left, Right'
            if ($hasDefault) { $t.Text = (@($default) | ForEach-Object { [string]$_ }) -join "`r`n" }
            $field['Control'] = $t; $field['Row'] = $t
        }
        'Table' {
            $g = New-Object System.Windows.Forms.DataGridView
            $g.AllowUserToAddRows = $true; $g.RowHeadersVisible = $false; $g.AutoSizeColumnsMode = 'Fill'
            $g.Height = 110; $g.Anchor = 'Left, Right'
            [void]$g.Columns.Add('Key', 'Key'); [void]$g.Columns.Add('Value', 'Value')
            if ($hasDefault -and $default -is [System.Collections.IDictionary]) {
                foreach ($k in @($default.Keys | Sort-Object)) { [void]$g.Rows.Add([string]$k, [string]$default[$k]) }
            }
            $field['Control'] = $g; $field['Row'] = $g
        }
        default {
            # Text, Path and Secret are single-line text boxes.
            $t = New-Object System.Windows.Forms.TextBox
            $t.Anchor = 'Left, Right'
            if ([string]$Option['Type'] -eq 'Secret') { $t.UseSystemPasswordChar = $true }
            if ($hasDefault) { $t.Text = [string]$default }
            $field['Control'] = $t; $field['Row'] = $t
            if ([string]$Option['Type'] -eq 'Path') {
                $row = New-Object System.Windows.Forms.TableLayoutPanel
                $row.ColumnCount = 2; $row.RowCount = 1; $row.AutoSize = $true; $row.Anchor = 'Left, Right'
                $row.Margin = New-Object System.Windows.Forms.Padding(0)
                [void]$row.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
                [void]$row.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
                $browse = New-Object System.Windows.Forms.Button
                $browse.Text = 'Browse...'; $browse.AutoSize = $true; $browse.Tag = $field
                $browse.Add_Click({ param($s, $e) Invoke-WoscapGuiConfigBrowse -Field $s.Tag })
                $row.Controls.Add($t, 0, 0); $row.Controls.Add($browse, 1, 0)
                $field['Browse'] = $browse; $field['Row'] = $row
            }
        }
    }
    $field
}

function Invoke-WoscapGuiConfigCredential {
    <# "Set..." click: asks through the credential seam; a cancelled prompt keeps the previous value. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Field)
    $c = Get-WoscapGuiCredential
    if ($c -is [pscredential]) {
        $Field['Value'] = $c
        $Field['Status'].Text = '(set)'
    }
}

function Invoke-WoscapGuiConfigBrowse {
    <# Path "Browse..." click: the option's PathKind picks the seam (File default, Folder, SaveFile); cancel keeps the text. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Field)
    $o = $Field['Option']
    $kind = if ($o.ContainsKey('PathKind') -and $o['PathKind']) { [string]$o['PathKind'] } else { 'File' }
    $p = switch ($kind) {
        'Folder'   { Get-WoscapGuiFolderPath }
        'SaveFile' { Get-WoscapGuiSavePath }
        default    { @(Get-WoscapGuiOpenPath -Filter 'All files (*.*)|*.*') | Select-Object -First 1 }
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$p)) { $Field['Control'].Text = [string]$p }
}

function Read-WoscapGuiConfigForm {
    <#
        @{ Config; Errors } from the form. Config is typed per option; optional empty fields
        are omitted. Errors name the option only, never its value.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] $Form)
    $tag = $Form.Tag
    $config = @{}
    $errors = New-Object System.Collections.Generic.List[string]
    if ($tag['Mode'] -eq 'Generic') {
        Read-WoscapGuiGenericConfig -Grid $tag['Grid'] -Config $config -Errors $errors
        return @{ Config = $config; Errors = $errors.ToArray() }
    }
    foreach ($field in $tag['Fields'].Values) {
        $o = $field['Option']
        $name = [string]$o['Name']
        $required = $o.ContainsKey('Required') -and [bool]$o['Required']
        $value = $null; $has = $false; $bad = $false
        $ctl = $field['Control']
        switch ([string]$o['Type']) {
            'Number' {
                $t = ([string]$ctl.Text).Trim()
                if ($t) {
                    $n = 0
                    if ([int]::TryParse($t, [ref]$n)) { $value = $n; $has = $true }
                    else { $errors.Add("'$name' must be a whole number."); $bad = $true }
                }
            }
            'Bool' { $value = [bool]$ctl.Checked; $has = $true }
            'Credential' { if ($field['Value'] -is [pscredential]) { $value = $field['Value']; $has = $true } }
            'Secret' {
                $t = [string]$ctl.Text
                if (-not [string]::IsNullOrWhiteSpace($t)) { $value = $t; $has = $true }
            }
            'List' {
                $items = [string[]]@(([string]$ctl.Text) -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                if ($items.Count -gt 0) { $value = $items; $has = $true }
            }
            'Table' {
                $h = @{}
                foreach ($row in $ctl.Rows) {
                    if ($row.IsNewRow) { continue }
                    $k = ([string]$row.Cells[0].Value).Trim()
                    $v = ([string]$row.Cells[1].Value).Trim()
                    if (-not $k -and -not $v) { continue }
                    if (-not $k) { $errors.Add("'$name': a row has a value but no key."); $bad = $true; continue }
                    if ($h.ContainsKey($k)) { $errors.Add("'$name': duplicate key '$k'."); $bad = $true; continue }
                    $h[$k] = $v
                }
                if ($h.Count -gt 0) { $value = $h; $has = $true }
            }
            default {
                $t = ([string]$ctl.Text).Trim()
                if ($t) { $value = $t; $has = $true }
            }
        }
        if ($bad) { continue }
        if ($has) { $config[$name] = $value }
        elseif ($required) { $errors.Add("'$name' is required.") }
    }
    @{ Config = $config; Errors = $errors.ToArray() }
}

function Read-WoscapGuiGenericConfig {
    <# Generic Key/Type/Value rows into -Config; blank rows and empty values are skipped. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Grid,
        [Parameter(Mandatory)][hashtable] $Config,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]] $Errors
    )
    foreach ($row in $Grid.Rows) {
        if ($row.IsNewRow) { continue }
        $k = ([string]$row.Cells['Key'].Value).Trim()
        $type = ([string]$row.Cells['Type'].Value).Trim()
        if (-not $type) { $type = 'Text' }
        $v = ([string]$row.Cells['Value'].Value).Trim()
        if (-not $k -and -not $v) { continue }
        if (-not $k) { $Errors.Add('A row has a value but no key.'); continue }
        if ($Config.ContainsKey($k)) { $Errors.Add("Duplicate key '$k'."); continue }
        if (-not $v) { continue }
        switch ($type) {
            'Number' {
                $n = 0
                if ([int]::TryParse($v, [ref]$n)) { $Config[$k] = $n } else { $Errors.Add("'$k' must be a whole number.") }
            }
            'Bool' {
                if ($v -in @('true', 'yes', '1')) { $Config[$k] = $true }
                elseif ($v -in @('false', 'no', '0')) { $Config[$k] = $false }
                else { $Errors.Add("'$k' must be true or false.") }
            }
            'List' {
                $items = [string[]]@($v -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                if ($items.Count -gt 0) { $Config[$k] = $items }
            }
            default { $Config[$k] = $v }
        }
    }
}

function Confirm-WoscapGuiConfigForm {
    <# Run click: closes with OK when valid, otherwise lists the problems and keeps the form open. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] $Form)
    $r = Read-WoscapGuiConfigForm -Form $Form
    if (@($r.Errors).Count -gt 0) {
        Show-WoscapGuiMessage -Text ("Please fix the following:`r`n" + (@($r.Errors) -join "`r`n")) -Caption ([string]$Form.Text)
        return $false
    }
    $Form.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $true
}

function Get-WoscapGuiConfigValue {
    <#
        The typed -Config hashtable: Text/Path string, Number int, Bool bool, Credential
        pscredential, Secret string, List string[], Table hashtable. Throws listing every
        problem (missing Required, bad number, duplicate key) when the form is not valid.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] $Form)
    $r = Read-WoscapGuiConfigForm -Form $Form
    if (@($r.Errors).Count -gt 0) { throw (@($r.Errors) -join ' ') }
    $r.Config
}

function Show-WoscapGuiConfigForm {
    <#
    .SYNOPSIS
        Shows the plugin config form modally (seam; mock it in tests).
    .DESCRIPTION
        Returns $null when cancelled, else the typed hashtable from Get-WoscapGuiConfigValue.
    .PARAMETER Options
        Schema entries for the hook, an empty list, or $null for the generic grid.
    .PARAMETER Title
        Form caption.
    .EXAMPLE
        $cfg = Show-WoscapGuiConfigForm -Options $opts -Title 'Run external scan'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]] $Options,
        [Parameter(Mandatory)][string] $Title
    )
    $d = New-WoscapGuiConfigForm -Options $Options -Title $Title
    try {
        if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return Get-WoscapGuiConfigValue -Form $d }
        $null
    } finally { $d.Dispose() }
}

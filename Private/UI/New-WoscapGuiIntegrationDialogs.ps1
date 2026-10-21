function New-WoscapGuiIntegrationSourceDialog {
    <#
        Builds (does not show) the first step of Import targets / Import findings: the source
        or report file and, for findings, "Correlate with current scan results" (disabled
        without -CanCorrelate). Next validates before closing and is not the AcceptButton.
    #>
    [CmdletBinding()]
    [OutputType([System.Windows.Forms.Form])]
    param(
        [Parameter(Mandatory)][ValidateSet('Targets', 'Findings')][string] $Mode,
        [Parameter(Mandatory)][string] $Integration,
        [switch] $CanCorrelate
    )
    $findings = $Mode -eq 'Findings'
    $title = if ($findings) { "Import findings - $Integration" } else { "Import targets - $Integration" }
    $f = New-WoscapGuiContentFrame -Title $title -Size 600, 250 -MinimumSize 460, 230 -Columns 2
    $form = $f.Form; $layout = $f.Layout

    $header = New-Object System.Windows.Forms.Label
    $header.Dock = 'Fill'; $header.AutoSize = $true
    $header.Text = if ($findings) { 'Choose the report file to import. The next step asks for the integration options.' }
        else { 'Choose the inventory or source file, or leave it blank if the integration reads targets from its server. The next step asks for the integration options.' }

    $path = New-Object System.Windows.Forms.TextBox
    $path.Anchor = 'Left, Right'
    $browse = New-Object System.Windows.Forms.Button
    $browse.Text = 'Browse...'; $browse.AutoSize = $true
    $strip = New-Object System.Windows.Forms.TableLayoutPanel
    $strip.ColumnCount = 2; $strip.RowCount = 1; $strip.Dock = 'Fill'; $strip.AutoSize = $true
    $strip.Margin = New-Object System.Windows.Forms.Padding(0)
    [void]$strip.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$strip.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::AutoSize)))
    $strip.Controls.Add($path, 0, 0); $strip.Controls.Add($browse, 1, 0)

    $correlate = $null
    if ($findings) {
        $correlate = New-Object System.Windows.Forms.CheckBox
        $correlate.AutoSize = $true; $correlate.Checked = $false; $correlate.Enabled = [bool]$CanCorrelate
        $correlate.Text = if ($CanCorrelate) { 'Correlate with current scan results' } else { 'Correlate with current scan results (run a scan first)' }
    }
    $spacer = New-Object System.Windows.Forms.Panel
    $spacer.Dock = 'Fill'; $spacer.Height = 0
    $b = New-WoscapGuiContentButtons -Form $form -ActionText 'Next...' -ActionResult ([System.Windows.Forms.DialogResult]::None)

    Add-WoscapGuiContentRow -Layout $layout -Control $header
    Add-WoscapGuiContentRow -Layout $layout -Label $(if ($findings) { 'Report file:' } else { 'Source file:' }) -Control $strip
    if ($correlate) { Add-WoscapGuiContentRow -Layout $layout -Control $correlate }
    Add-WoscapGuiContentRow -Layout $layout -Control $spacer -Fill
    Add-WoscapGuiContentRow -Layout $layout -Control $b.Panel

    $filter = if ($findings) { 'Report (*.xml)|*.xml|All files (*.*)|*.*' }
        else { 'Inventory (*.yml;*.yaml;*.ini)|*.yml;*.yaml;*.ini|All files (*.*)|*.*' }
    $tag = @{ Mode = $Mode; Header = $header; Path = $path; Browse = $browse; Correlate = $correlate
        Filter = $filter; Next = $b.Action; Cancel = $b.Cancel }
    $form.Tag = $tag
    $browse.Tag = $tag
    $browse.Add_Click({ param($s, $e) Invoke-WoscapGuiIntegrationSourceBrowse -Tag $s.Tag })
    $b.Action.Add_Click({
        param($s, $e)
        $owner = $s.FindForm()
        if ($owner) { [void](Confirm-WoscapGuiIntegrationSourceDialog -Form $owner) }
    })
    $form
}

function Invoke-WoscapGuiIntegrationSourceBrowse {
    <# Browse click: fills the path from the open-file seam; a cancelled pick keeps it. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $p = @(Get-WoscapGuiOpenPath -Filter $Tag['Filter']) | Select-Object -First 1
    if (-not [string]::IsNullOrWhiteSpace([string]$p)) { $Tag['Path'].Text = [string]$p }
}

function Get-WoscapGuiIntegrationSourceChoice {
    <#
        @{ Path; Correlate } from the source dialog, Path trimmed. Throws when a findings
        report is missing or a given file does not exist (unless -SkipValidation).
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][hashtable] $Tag, [switch] $SkipValidation)
    $path = ([string]$Tag['Path'].Text).Trim()
    $correlate = $null -ne $Tag['Correlate'] -and $Tag['Correlate'].Enabled -and $Tag['Correlate'].Checked
    if (-not $SkipValidation) {
        if ($Tag['Mode'] -eq 'Findings' -and -not $path) { throw 'Choose the report file to import.' }
        if ($path -and -not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "File not found: $path" }
    }
    @{ Path = $path; Correlate = [bool]$correlate }
}

function Confirm-WoscapGuiIntegrationSourceDialog {
    <# Next click: closes with OK when valid, otherwise shows why and keeps the dialog open. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][System.Windows.Forms.Form] $Form)
    try {
        [void](Get-WoscapGuiIntegrationSourceChoice -Tag $Form.Tag)
    } catch {
        Show-WoscapGuiMessage -Text $_.Exception.Message -Caption ([string]$Form.Text)
        return $false
    }
    $Form.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $true
}

function Show-WoscapGuiIntegrationSourceDialog {
    <# Seam: $null on cancel, else @{ Path; Correlate } (Path '' when no source file was given). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Targets', 'Findings')][string] $Mode,
        [Parameter(Mandatory)][string] $Integration,
        [switch] $CanCorrelate
    )
    $d = New-WoscapGuiIntegrationSourceDialog -Mode $Mode -Integration $Integration -CanCorrelate:$CanCorrelate
    try {
        if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return Get-WoscapGuiIntegrationSourceChoice -Tag $d.Tag }
        $null
    } finally { $d.Dispose() }
}

function ConvertTo-WoscapGuiFindingRow {
    <# Flat display row for one finding or link; list values are joined with ', '. #>
    [CmdletBinding()]
    param([AllowNull()] $InputObject, [Parameter(Mandatory)][string[]] $Property)
    $row = [ordered]@{}
    foreach ($p in $Property) {
        $v = if ($null -eq $InputObject -or $InputObject -is [string]) { $null } else { Get-WoscapObjectProperty $InputObject $p $null }
        $row[$p] = (@($v) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ }) -join ', '
    }
    # A bare value (e.g. a string) still shows, under the first column.
    if ($InputObject -is [string]) { $row[$Property[0]] = $InputObject }
    [pscustomobject]$row
}

function New-WoscapGuiIntegrationFindingsDialog {
    <#
        Builds (does not show) the findings result: a summary line, the findings grid and,
        when -Links is not $null (a correlated import), the links to scan results.
    #>
    [CmdletBinding()]
    [OutputType([System.Windows.Forms.Form])]
    param(
        [Parameter(Mandatory)][string] $Title,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]] $Findings,
        [AllowNull()][AllowEmptyCollection()][object[]] $Links
    )
    $f = New-WoscapGuiContentFrame -Title $Title -Size 820, 520 -MinimumSize 560, 380
    $form = $f.Form; $layout = $f.Layout

    $props = 'Host', 'Severity', 'Id', 'Name', 'Cve', 'Cce', 'Port'
    $rows = @(foreach ($x in @($Findings)) { ConvertTo-WoscapGuiFindingRow -InputObject $x -Property $props })
    $grid = New-WoscapGuiContentGrid -Header 'Host', 'Severity', 'Id', 'Name', 'CVE', 'CCE', 'Port' -Property $props -Rows $rows

    $summary = New-Object System.Windows.Forms.Label
    $summary.Dock = 'Fill'; $summary.AutoSize = $false; $summary.AutoEllipsis = $true
    $summary.Height = $summary.PreferredHeight
    $text = '{0} finding(s).' -f $rows.Count

    Add-WoscapGuiContentRow -Layout $layout -Control $summary
    Add-WoscapGuiContentRow -Layout $layout -Control $grid -Fill
    $linkGrid = $null
    if ($null -ne $Links) {
        $lprops = 'Host', 'RuleId', 'FindingId', 'MatchedOn'
        $lrows = @(foreach ($x in @($Links)) { ConvertTo-WoscapGuiFindingRow -InputObject $x -Property $lprops })
        $linkGrid = New-WoscapGuiContentGrid -Header 'Host', 'Rule', 'Finding', 'Matched on' -Property $lprops -Rows $lrows
        $text += ' {0} link(s) to current scan results.' -f $lrows.Count
        Add-WoscapGuiContentRow -Layout $layout -Control $linkGrid -Fill
    }
    $summary.Text = $text

    $panel = New-Object System.Windows.Forms.FlowLayoutPanel
    $panel.Dock = 'Fill'; $panel.AutoSize = $true; $panel.FlowDirection = 'RightToLeft'; $panel.WrapContents = $false
    $close = New-Object System.Windows.Forms.Button
    $close.Text = 'Close'; $close.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $panel.Controls.Add($close)
    $form.CancelButton = $close
    Add-WoscapGuiContentRow -Layout $layout -Control $panel

    $form.Tag = @{ Summary = $summary; Findings = $grid; Links = $linkGrid; Close = $close }
    $form
}

function Show-WoscapGuiIntegrationFindings {
    <# Seam: shows the findings result until closed. -Links $null means not correlated. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Title,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]] $Findings,
        [AllowNull()][AllowEmptyCollection()][object[]] $Links
    )
    $d = New-WoscapGuiIntegrationFindingsDialog -Title $Title -Findings $Findings -Links $Links
    try { [void]$d.ShowDialog() } finally { $d.Dispose() }
}

function Format-WoscapGuiIntegrationReturn {
    <# One line per value a hook returned: bools and strings as-is, objects as Name=Value pairs. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyCollection()][object[]] $Value)
    $lines = foreach ($v in @($Value)) {
        if ($null -eq $v) { continue }
        if ($v -is [string] -or $v -is [bool] -or $v -is [ValueType]) { [string]$v; continue }
        $pairs = if ($v -is [System.Collections.IDictionary]) {
            foreach ($k in $v.Keys) { '{0}={1}' -f $k, ((@($v[$k]) | ForEach-Object { [string]$_ }) -join ', ') }
        } else {
            foreach ($p in $v.PSObject.Properties) { '{0}={1}' -f $p.Name, ((@($p.Value) | ForEach-Object { [string]$_ }) -join ', ') }
        }
        @($pairs) -join '; '
    }
    if (@($lines).Count -eq 0) { return '(no return value)' }
    @($lines) -join "`r`n"
}

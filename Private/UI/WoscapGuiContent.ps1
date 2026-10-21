function Resolve-WoscapGuiDisaTerms {
    <#
        Decides whether a download/update may proceed and whether to pass -AcceptDisaTerms.
        Never writes the marker: the caller persists it only after the operation succeeds.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $CacheRoot)

    if (Test-WoscapDisaTermsAccepted -CacheRoot $CacheRoot) {
        return @{ Proceed = $true; AcceptSwitch = $false; Remember = $false }
    }
    # A failing dialog must never count as acceptance.
    try { $answer = Show-WoscapGuiDisaTermsDialog -Notice (Get-WoscapDisaNotice) } catch { $answer = $null }
    if ($null -eq $answer) {
        return @{ Proceed = $false; AcceptSwitch = $false; Remember = $false }
    }
    $remember = $false
    if ($answer -is [System.Collections.IDictionary] -and $answer.Contains('Remember')) { $remember = [bool]$answer['Remember'] }
    @{ Proceed = $true; AcceptSwitch = $true; Remember = $remember }
}

function Get-WoscapGuiRemoveScope {
    <# Splat for Remove-WoscapBenchmark; throws rather than ever yielding an empty Benchmark/Revision. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] $Row, [switch] $AllRevisions)

    $get = {
        param($Name)
        $p = $Row.PSObject.Properties[$Name]
        if ($p -and $null -ne $p.Value) { ([string]$p.Value).Trim() } else { '' }
    }
    $benchmark = & $get 'Benchmark'
    if (-not $benchmark) { throw 'woscap: the selected row has no Benchmark; nothing to remove.' }
    if ($AllRevisions) { return @{ Benchmark = $benchmark } }
    $revision = & $get 'Revision'
    if (-not $revision) { throw "woscap: the selected row for '$benchmark' has no Revision; refusing to remove." }
    @{ Benchmark = $benchmark; Revision = $revision }
}

function Find-WoscapGuiContentPack {
    <# Exact, case-insensitive match of a cached benchmark name to a content pack; the pack's own name or $null. #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string] $Benchmark,
        [AllowNull()][AllowEmptyCollection()][string[]] $Available
    )
    if ([string]::IsNullOrWhiteSpace($Benchmark)) { return $null }
    foreach ($name in @($Available)) {
        if ($name -ieq $Benchmark.Trim()) { return $name }
    }
    $null
}

function Get-WoscapGuiContentDestination {
    <# Trimmed Cache folder text, or $null when blank (blank means the default cache root). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $text = $Tag['ContentDestination'].Text
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $text.Trim()
}

function Update-WoscapGuiContentView {
    <#
        Re-lists the cache into the Content grid (row.Tag = the Get-WoscapBenchmark object) and
        rebuilds the filter from every cached benchmark. Never throws: a failure clears the grid
        and shows in the status line.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)

    # Rebuilding the filter items raises its SelectedIndexChanged, which calls back here.
    if ($Tag['ContentRefreshing']) { return }
    $Tag['ContentRefreshing'] = $true
    $Tag['ContentLoaded'] = $true
    $grid = $Tag['ContentGrid']; $filter = $Tag['ContentFilter']
    try {
        $grid.Rows.Clear()
        $splat = @{ ErrorAction = 'Stop' }
        $destination = Get-WoscapGuiContentDestination -Tag $Tag
        if ($destination) { $splat['Destination'] = $destination }
        $all = @(Get-WoscapBenchmark @splat)

        $names = @($all | ForEach-Object { [string]$_.Benchmark } | Sort-Object -Unique)
        $wanted = [string]$filter.SelectedItem
        if ($wanted -notin $names) { $wanted = 'All' }
        $filter.BeginUpdate()
        try {
            $filter.Items.Clear()
            [void]$filter.Items.Add('All')
            foreach ($n in $names) { [void]$filter.Items.Add($n) }
            $filter.SelectedItem = $wanted
        } finally { $filter.EndUpdate() }

        $rows = if ($wanted -eq 'All') { $all } else { @(Get-WoscapBenchmark @splat -Benchmark $wanted) }
        foreach ($r in $rows) {
            $hash = [string](Get-WoscapObjectProperty $r 'ContentHash' '')
            if ($hash.Length -gt 12) { $hash = $hash.Substring(0, 12) }
            $values = @(
                [string](Get-WoscapObjectProperty $r 'Benchmark' ''), [string](Get-WoscapObjectProperty $r 'Revision' ''),
                [string](Get-WoscapObjectProperty $r 'Title' ''), $hash, [string](Get-WoscapObjectProperty $r 'SourceUrl' '')
            )
            $idx = $grid.Rows.Add([object[]]$values)
            $grid.Rows[$idx].Tag = $r
        }
        $Tag['ContentStatus'].Text = '{0} cached revision(s) in {1}' -f @($rows).Count, (Get-WoscapContentCacheRoot -Destination $destination)
    } catch {
        $grid.Rows.Clear()
        $Tag['ContentStatus'].Text = 'Refresh failed: ' + $_.Exception.Message
    } finally {
        # A rebind must not leave an implicit selection that Remove / Use for scan would act on.
        $grid.ClearSelection()
        Update-WoscapGuiContentSelection -Tag $Tag
        $Tag['ContentRefreshing'] = $false
    }
}

function Update-WoscapGuiContentSelection {
    <# Remove and Use for scan (button + menu) are enabled only while a grid row is selected and no content job runs. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $selected = (-not $Tag['ContentBusy']) -and $Tag['ContentGrid'].SelectedRows.Count -gt 0
    Set-WoscapGuiActionEnabled -Tag $Tag -Action ContentRemove -Enabled $selected
    Set-WoscapGuiActionEnabled -Tag $Tag -Action ContentUseForScan -Enabled $selected
}

function Add-WoscapGuiProfile {
    <# Appends profile paths to the list, skipping case-insensitive duplicates. List order
       is the -ProfilePath order. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [string[]] $Path = @())
    $list = $Tag['Profiles']
    foreach ($p in @($Path)) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $dupe = @($list.Items | Where-Object { [string]::Equals([string]$_, $p, [System.StringComparison]::OrdinalIgnoreCase) })
        if ($dupe.Count -eq 0) { [void]$list.Items.Add($p) }
    }
    Update-WoscapGuiProfileButton -Tag $Tag
}

function Remove-WoscapGuiProfile {
    <# Drops the selected profile; selection moves to the next row (or the new last). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $list = $Tag['Profiles']
    $i = $list.SelectedIndex
    if ($i -lt 0) { return }
    $list.Items.RemoveAt($i)
    if ($list.Items.Count -gt 0) { $list.SelectedIndex = [Math]::Min($i, $list.Items.Count - 1) }
    Update-WoscapGuiProfileButton -Tag $Tag
}

function Move-WoscapGuiProfile {
    <# Moves the selected profile by -1 (up) or +1 (down); no-op at either end. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][ValidateSet(-1, 1)][int] $Offset)
    $list = $Tag['Profiles']
    $i = $list.SelectedIndex
    $j = $i + $Offset
    if ($i -lt 0 -or $j -lt 0 -or $j -ge $list.Items.Count) { return }
    $item = $list.Items[$i]
    $list.Items.RemoveAt($i)
    $list.Items.Insert($j, $item)
    $list.SelectedIndex = $j
    Update-WoscapGuiProfileButton -Tag $Tag
}

function Update-WoscapGuiProfileButton {
    <# Enables Remove/Up/Down only when that action would do something. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $list = $Tag['Profiles']
    $i = $list.SelectedIndex
    $Tag['ProfileRemove'].Enabled = $i -ge 0
    $Tag['ProfileUp'].Enabled     = $i -gt 0
    $Tag['ProfileDown'].Enabled   = $i -ge 0 -and $i -lt ($list.Items.Count - 1)
}

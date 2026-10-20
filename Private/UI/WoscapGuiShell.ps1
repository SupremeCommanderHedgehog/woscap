function Set-WoscapGuiActionEnabled {
    <# Enables/disables an action's button and its menu item together so they never disagree. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable] $Tag,
        [Parameter(Mandatory)][ValidateSet('Run', 'Export')][string] $Action,
        [Parameter(Mandatory)][bool] $Enabled
    )
    $Tag[$Action].Enabled = $Enabled
    if ($Tag.ContainsKey("Menu$Action") -and $Tag["Menu$Action"]) { $Tag["Menu$Action"].Enabled = $Enabled }
}

function Set-WoscapGuiAdvanced {
    <# Shows/hides the Advanced group. State lives in Tag because Control.Visible reads
       false until the form is shown. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][bool] $Expanded)
    $Tag['AdvancedExpanded'] = $Expanded
    $Tag['AdvancedGroup'].Visible = $Expanded
    $Tag['AdvancedToggle'].Text = if ($Expanded) { '[-] Advanced' } else { '[+] Advanced' }
}

function Show-WoscapGuiAdvancedOption {
    <# Scan > Advanced options: jump to the Scan tab with Advanced expanded. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $Tag['Tabs'].SelectedTab = $Tag['ScanTab']
    Set-WoscapGuiAdvanced -Tag $Tag -Expanded $true
}

function Update-WoscapGuiContentHint {
    <# Display-only hint of the content pack Invoke-WoscapScan uses when ContentPath is blank. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $bench = [string]$Tag['Benchmark'].SelectedItem
    $Tag['ContentPathDefault'].Text = if ($bench) {
        'Default: ' + (Join-Path $script:WoscapModuleRoot (Join-Path 'Content' $bench))
    } else { '' }
}

function Show-WoscapGuiAbout {
    <# Help > About. #>
    [CmdletBinding()]
    param()
    $version = $MyInvocation.MyCommand.Module.Version
    Show-WoscapGuiMessage -Text "woscap $version`r`nWindows STIG scanner." -Caption 'About woscap'
}

function Open-WoscapGuiManual {
    <# Help > Open manual: hands MANUAL.md to the shell's default handler. #>
    [CmdletBinding()]
    param([string] $Path = (Join-Path $script:WoscapModuleRoot 'MANUAL.md'))
    if (-not (Test-Path -LiteralPath $Path)) {
        Show-WoscapGuiMessage -Text "Manual not found: $Path"
        return
    }
    Invoke-Item -LiteralPath $Path
}

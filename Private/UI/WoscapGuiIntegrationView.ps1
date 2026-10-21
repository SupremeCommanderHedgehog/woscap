function Get-WoscapGuiIntegrationAction {
    <# Integrations-tab action -> the capability hook it runs, in button order. #>
    [CmdletBinding()]
    param()
    [ordered]@{
        IntegrationImportTargets     = 'Get-Targets'
        IntegrationImportFindings    = 'Import-Findings'
        IntegrationRunScan           = 'Invoke-ExternalScan'
        IntegrationExportFindings    = 'Export-Findings'
        IntegrationExportRemediation = 'New-Remediation'
    }
}

function Get-WoscapGuiIntegrationFolder {
    <# Trimmed Plugin folder text, or $null when blank (blank means the bundled Integrations folder). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $text = $Tag['IntegrationPath'].Text
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $text.Trim()
}

function Resolve-WoscapGuiIntegrationRoot {
    <# Full path of the folder a listing reads (blank = bundled); throws on an invalid path. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string] $Folder)
    [System.IO.Path]::GetFullPath((Get-WoscapPluginRoot -Path $Folder)).TrimEnd([char[]]@('\', '/'))
}

function Update-WoscapGuiIntegrationView {
    <#
        Re-lists the Plugin folder into the grid (row.Tag = the Get-WoscapIntegration object);
        non-conformant rows are greyed. Never throws: a failure clears the grid and shows in
        the status line. The selection is always cleared so no action targets a stale row.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $Tag['IntegrationLoaded'] = $true
    $grid = $Tag['IntegrationGrid']
    try {
        $grid.Rows.Clear()
        $Tag['IntegrationListedRoot'] = $null
        $folder = Get-WoscapGuiIntegrationFolder -Tag $Tag
        $root = Resolve-WoscapGuiIntegrationRoot -Folder $folder
        if (-not (Test-Path -LiteralPath $root)) { throw "Plugin folder not found: $root" }
        $splat = @{ ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
        if ($folder) { $splat['Path'] = $folder }
        $all = @(Get-WoscapIntegration @splat)
        # Integration actions act only on the folder these rows came from.
        $Tag['IntegrationListedRoot'] = $root

        $grey = 0
        foreach ($p in $all) {
            $conformant = [bool](Get-WoscapObjectProperty $p 'Conformant' $false)
            $caps = @(Get-WoscapObjectProperty $p 'Capabilities' @()) | ForEach-Object { [string]$_ }
            $values = @(
                [string](Get-WoscapObjectProperty $p 'Name' ''), [string](Get-WoscapObjectProperty $p 'Version' ''),
                $(if ($conformant) { 'Yes' } else { 'No' }), (@($caps) -join ', ')
            )
            $idx = $grid.Rows.Add([object[]]$values)
            $row = $grid.Rows[$idx]
            $row.Tag = $p
            if (-not $conformant) {
                $grey++
                $row.DefaultCellStyle.ForeColor = [System.Drawing.SystemColors]::GrayText
            }
        }
        $note = if ($grey -gt 0) { " ($grey not conformant)" } else { '' }
        $Tag['IntegrationStatus'].Text = '{0} integration(s) in {1}{2}' -f $all.Count, $root, $note
    } catch {
        $grid.Rows.Clear()
        $Tag['IntegrationStatus'].Text = 'Refresh failed: ' + $_.Exception.Message
    } finally {
        $grid.ClearSelection()
        Update-WoscapGuiIntegrationSelection -Tag $Tag
    }
}

function Get-WoscapGuiIntegrationSelectedPlugin {
    <# The Get-WoscapIntegration object of the selected grid row, or $null. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $rows = $Tag['IntegrationGrid'].SelectedRows
    if ($rows.Count -eq 0) { return $null }
    $rows[0].Tag
}

function Update-WoscapGuiIntegrationSelection {
    <#
        Each action (button + menu) is enabled only for a selected conformant plugin that
        declares its hook, and never while an integration or content job runs.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $plugin = Get-WoscapGuiIntegrationSelectedPlugin -Tag $Tag
    $idle = $Tag['Busy'] -notin @('Integration', 'Content')
    $usable = $idle -and $null -ne $plugin -and [bool](Get-WoscapObjectProperty $plugin 'Conformant' $false)
    $caps = @(if ($usable) { Get-WoscapObjectProperty $plugin 'Capabilities' @() })
    foreach ($e in (Get-WoscapGuiIntegrationAction).GetEnumerator()) {
        Set-WoscapGuiActionEnabled -Tag $Tag -Action $e.Key -Enabled ($usable -and ($caps -contains $e.Value))
    }
}

function Set-WoscapGuiIntegrationBusy {
    <#
        One background job at a time: an integration job disables every integration and
        content action and the Scan tab's Run/Remediate; going idle restores them under
        their usual rules.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][bool] $Busy, [string] $Status = '')
    $Tag['Busy'] = if ($Busy) { 'Integration' } else { $null }
    Update-WoscapGuiIntegrationSelection -Tag $Tag
    Set-WoscapGuiActionEnabled -Tag $Tag -Action ContentDownload -Enabled (-not $Busy)
    Set-WoscapGuiActionEnabled -Tag $Tag -Action ContentUpdate -Enabled (-not $Busy)
    Update-WoscapGuiContentSelection -Tag $Tag
    Set-WoscapGuiActionEnabled -Tag $Tag -Action Run -Enabled (-not $Busy)
    $remediable = @($Tag['Results']).Count -gt 0 -and -not $Tag['ResultsStale'] -and $null -ne $Tag['ResultsContext']
    Set-WoscapGuiActionEnabled -Tag $Tag -Action Remediate -Enabled ((-not $Busy) -and $remediable)
    if ($Status) { $Tag['IntegrationStatus'].Text = $Status }
}

function Get-WoscapGuiIntegrationTarget {
    <#
        @{ Plugin; Name; PluginPath } for running -Hook on the selected plugin, or $null after
        a message. Refuses a non-conformant plugin, a hook it does not declare, and a Plugin
        folder edited since the grid was listed. PluginPath is the plugin's own folder when a
        Plugin folder is set, else $null (bundled plugin by name).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][string] $Hook)
    $plugin = Get-WoscapGuiIntegrationSelectedPlugin -Tag $Tag
    if (-not $plugin) {
        Show-WoscapGuiMessage -Text 'Select an integration first.'
        return $null
    }
    $name = [string](Get-WoscapObjectProperty $plugin 'Name' '')
    if (-not [bool](Get-WoscapObjectProperty $plugin 'Conformant' $false)) {
        Show-WoscapGuiMessage -Text "Integration '$name' is not conformant and cannot be used."
        return $null
    }
    if (@(Get-WoscapObjectProperty $plugin 'Capabilities' @()) -notcontains $Hook) {
        Show-WoscapGuiMessage -Text "Integration '$name' does not support $Hook."
        return $null
    }
    $folder = Get-WoscapGuiIntegrationFolder -Tag $Tag
    try {
        $root = Resolve-WoscapGuiIntegrationRoot -Folder $folder
    } catch {
        Show-WoscapGuiMessage -Text "Plugin folder is not a valid path: $($_.Exception.Message)"
        return $null
    }
    $listed = [string]$Tag['IntegrationListedRoot']
    if (-not $listed -or $root -ne $listed) {
        Show-WoscapGuiMessage -Text "The Plugin folder changed since the list was shown ($listed). Click Refresh first."
        return $null
    }
    @{
        Plugin     = $plugin
        Name       = $name
        PluginPath = if ($folder) { [string](Get-WoscapObjectProperty $plugin 'Path' '') } else { $null }
    }
}

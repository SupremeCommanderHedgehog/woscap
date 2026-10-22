function New-WoscapGuiMenu {
    <#
        Builds the main MenuStrip. Returns @{ Menu; Run; Remediate; Export; ResetSettings; Exit; Advanced; ContentDownload;
        ContentUpdate; ContentRemove; ContentUseForScan; ContentRefresh; OpenContent; IntegrationImportTargets;
        IntegrationImportFindings; IntegrationRunScan; IntegrationExportFindings; IntegrationExportRemediation;
        IntegrationRefresh; OpenIntegrations; Manual; About } so the form can wire Click handlers. No logic here.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $menu = New-Object System.Windows.Forms.MenuStrip
    $menu.Dock = 'Top'

    $newItem = {
        param([string] $Text, $Keys)
        $item = New-Object System.Windows.Forms.ToolStripMenuItem
        $item.Text = $Text
        if ($Keys) { $item.ShortcutKeys = $Keys }
        $item
    }
    $K = [System.Windows.Forms.Keys]

    $export   = & $newItem '&Export results...' ($K::Control -bor $K::E)
    $resetSettings = & $newItem 'Reset &settings...' $null
    $exit     = & $newItem 'E&xit' $null
    $run      = & $newItem '&Run' $K::F5
    $remediate = & $newItem '&Remediate...' $null
    $advanced = & $newItem '&Advanced options' $null
    $contentDownload   = & $newItem '&Download...' $null
    $contentUpdate     = & $newItem '&Update...' $null
    $contentRemove     = & $newItem '&Remove...' $null
    $contentUseForScan = & $newItem 'Use for &scan' $null
    $contentRefresh    = & $newItem 'Re&fresh' $null
    $intTargets  = & $newItem 'Import &targets...' $null
    $intFindings = & $newItem 'Import fi&ndings...' $null
    $intRunScan  = & $newItem 'Run e&xternal scan...' $null
    $intExport   = & $newItem '&Export findings...' $null
    $intRemed    = & $newItem 'Export re&mediation...' $null
    $intRefresh  = & $newItem 'Re&fresh' $null
    $openContent      = & $newItem 'Open &Content tab' $null
    $openIntegrations = & $newItem 'Open &Integrations tab' $null
    $manual   = & $newItem 'Open &manual' $null
    $about    = & $newItem '&About woscap' $null

    $file = & $newItem '&File' $null
    [void]$file.DropDownItems.Add($export)
    [void]$file.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    [void]$file.DropDownItems.Add($resetSettings)
    [void]$file.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    [void]$file.DropDownItems.Add($exit)
    $scan = & $newItem '&Scan' $null
    [void]$scan.DropDownItems.AddRange([System.Windows.Forms.ToolStripItem[]]@($run, $remediate, $advanced))
    $content = & $newItem '&Content' $null
    [void]$content.DropDownItems.AddRange([System.Windows.Forms.ToolStripItem[]]@(
        $contentDownload, $contentUpdate, $contentRemove, $contentUseForScan, $contentRefresh,
        (New-Object System.Windows.Forms.ToolStripSeparator), $openContent))
    $integrations = & $newItem '&Integrations' $null
    [void]$integrations.DropDownItems.AddRange([System.Windows.Forms.ToolStripItem[]]@(
        $intTargets, $intFindings, $intRunScan, $intExport, $intRemed, $intRefresh,
        (New-Object System.Windows.Forms.ToolStripSeparator), $openIntegrations))
    $help = & $newItem '&Help' $null
    [void]$help.DropDownItems.AddRange([System.Windows.Forms.ToolStripItem[]]@($manual, $about))

    [void]$menu.Items.AddRange([System.Windows.Forms.ToolStripItem[]]@($file, $scan, $content, $integrations, $help))

    @{
        Menu = $menu; Run = $run; Remediate = $remediate; Export = $export; ResetSettings = $resetSettings; Exit = $exit; Advanced = $advanced
        ContentDownload = $contentDownload; ContentUpdate = $contentUpdate; ContentRemove = $contentRemove
        ContentUseForScan = $contentUseForScan; ContentRefresh = $contentRefresh
        IntegrationImportTargets = $intTargets; IntegrationImportFindings = $intFindings; IntegrationRunScan = $intRunScan
        IntegrationExportFindings = $intExport; IntegrationExportRemediation = $intRemed; IntegrationRefresh = $intRefresh
        OpenContent = $openContent; OpenIntegrations = $openIntegrations; Manual = $manual; About = $about
    }
}

function New-WoscapGuiMenu {
    <#
        Builds the main MenuStrip. Returns @{ Menu; Run; Remediate; Export; Exit; Advanced; OpenContent;
        OpenIntegrations; Manual; About } so the form can wire Click handlers. No logic here.
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
    $exit     = & $newItem 'E&xit' $null
    $run      = & $newItem '&Run' $K::F5
    $remediate = & $newItem '&Remediate...' $null
    $advanced = & $newItem '&Advanced options' $null
    $openContent      = & $newItem 'Open &Content tab' $null
    $openIntegrations = & $newItem 'Open &Integrations tab' $null
    $manual   = & $newItem 'Open &manual' $null
    $about    = & $newItem '&About woscap' $null

    $file = & $newItem '&File' $null
    [void]$file.DropDownItems.Add($export)
    [void]$file.DropDownItems.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    [void]$file.DropDownItems.Add($exit)
    $scan = & $newItem '&Scan' $null
    [void]$scan.DropDownItems.AddRange([System.Windows.Forms.ToolStripItem[]]@($run, $remediate, $advanced))
    $content = & $newItem '&Content' $null
    [void]$content.DropDownItems.Add($openContent)
    $integrations = & $newItem '&Integrations' $null
    [void]$integrations.DropDownItems.Add($openIntegrations)
    $help = & $newItem '&Help' $null
    [void]$help.DropDownItems.AddRange([System.Windows.Forms.ToolStripItem[]]@($manual, $about))

    [void]$menu.Items.AddRange([System.Windows.Forms.ToolStripItem[]]@($file, $scan, $content, $integrations, $help))

    @{
        Menu = $menu; Run = $run; Remediate = $remediate; Export = $export; Exit = $exit; Advanced = $advanced
        OpenContent = $openContent; OpenIntegrations = $openIntegrations; Manual = $manual; About = $about
    }
}

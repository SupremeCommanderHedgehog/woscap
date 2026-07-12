function Show-WoscapGui {
    <#
        .SYNOPSIS
        Launches the woscap Windows Forms front-end.
        .DESCRIPTION
        Opens an interactive window that drives Invoke-WoscapScan / Export-WoscapResult:
        pick a benchmark + XCCDF, choose targets/profile, run a scan with live progress,
        view results in a filterable grid, and export. Requires an interactive desktop
        session (not available on Server Core / headless hosts); use the CLI cmdlets for
        unattended/headless scanning. The GUI holds no evaluation/exception/export logic
        of its own.
        .EXAMPLE
        Show-WoscapGui
    #>
    [CmdletBinding()]
    param()
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $form = New-WoscapMainForm
    try { [void]$form.ShowDialog() } finally { $form.Dispose() }
}

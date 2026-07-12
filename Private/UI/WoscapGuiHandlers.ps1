function Show-WoscapGuiMessage {
    <# Thin seam over MessageBox so handlers are testable (mock this in tests). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Text, [string] $Caption = 'woscap')
    [void][System.Windows.Forms.MessageBox]::Show($Text, $Caption)
}

function Get-WoscapGuiSavePath {
    <# Thin seam over SaveFileDialog so the Export handler is testable. Returns the
       chosen path, or $null if cancelled. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Format)
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = "$Format files|*.$Format|All files|*.*"
    $dlg.DefaultExt = $Format
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $dlg.FileName } else { $null }
}

function Get-WoscapGuiCredential {
    <# Thin seam over Get-Credential so the Run handler is testable and never pops a real
       Windows credential dialog in tests. Returns a [pscredential], or $null if cancelled. #>
    [CmdletBinding()]
    [OutputType([pscredential])]
    param()
    Get-Credential
}

function Update-WoscapGuiView {
    <#
        Re-applies the current severity/status/find filter to the full result set and
        rebinds the grid. Pure presentation; never re-scans. A NAMED function (not a
        closure) so it resolves module-private helpers on every invocation path.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $filtered = Select-WoscapGuiRow -Result @($Tag['Results']) `
        -Severity ([string]$Tag['FilterSeverity'].SelectedItem) `
        -Status   ([string]$Tag['FilterStatus'].SelectedItem) `
        -Find     ([string]$Tag['Find'].Text)
    Update-WoscapGuiGrid -Grid $Tag['Grid'] -Rows @($filtered)
}

function Invoke-WoscapGuiRun {
    <#
        The Run action: validate inputs, build the scan splat, and start the background
        scan. NAMED function -> resolves module-private helpers on any invocation path.
        Stores the tag in $script:WoscapGuiTag so the scan CALLBACKS (plain scriptblocks
        the executor invokes later) can reach the controls. The GUI is single-window, so
        one 'current tag' is safe.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $script:WoscapGuiTag = $Tag

    $xccdfPath = [string]$Tag['Xccdf'].Text
    if ([string]::IsNullOrWhiteSpace($xccdfPath) -or -not (Test-Path -LiteralPath $xccdfPath)) {
        Show-WoscapGuiMessage -Text 'Select a valid XCCDF (.xml) file before running.'
        return
    }
    $benchmark = [string]$Tag['Benchmark'].SelectedItem
    if ([string]::IsNullOrWhiteSpace($benchmark)) {
        Show-WoscapGuiMessage -Text 'Select a benchmark before running. (No content packs were found under Content/.)'
        return
    }
    $cred = $null
    if ($Tag['UseCred'].Checked) {
        $cred = Get-WoscapGuiCredential
        if (-not $cred) { return }   # cancelled
    }
    $splat = ConvertTo-WoscapGuiScanParameter -XccdfPath $xccdfPath `
        -Benchmark $benchmark `
        -Targets   ([string]$Tag['Targets'].Text) `
        -ProfilePath ([string]$Tag['Profile'].Text) `
        -Credential $cred

    $Tag['Run'].Enabled = $false
    $Tag['Status'].Text = 'Scanning...'

    # Callbacks are PLAIN scriptblocks (NOT closures). A plain scriptblock keeps the
    # module's session state, so it resolves module-private functions when the executor
    # (or a test mock) invokes it via '&'. It reaches the controls via $script:WoscapGuiTag.
    $onProgress = {
        param($Percent, $Status, $Indeterminate)
        $t = $script:WoscapGuiTag
        $t['Progress'].Style = if ($Indeterminate) { 'Marquee' } else { 'Continuous' }
        if (-not $Indeterminate) { $t['Progress'].Value = $Percent }
        $t['Status'].Text = $Status
    }
    $onComplete = {
        param($Results)
        $t = $script:WoscapGuiTag
        $t['Results'].Clear()
        foreach ($r in @($Results)) { $t['Results'].Add($r) }
        Update-WoscapGuiView -Tag $t
        $t['Count'].Text = "$(@($t['Results']).Count) rules"
        $t['Export'].Enabled = (@($t['Results']).Count -gt 0)
        $t['Progress'].Style = 'Continuous'; $t['Progress'].Value = 0
        $t['Status'].Text = 'Done.'
        $t['Run'].Enabled = $true
    }
    $onError = {
        param($Message)
        $t = $script:WoscapGuiTag
        Show-WoscapGuiMessage -Text "Scan failed: $Message"
        $t['Status'].Text = 'Failed.'
        $t['Run'].Enabled = $true
    }

    # Starting the background scan can fail synchronously (runspace BeginInvoke or timer
    # Start). Re-enable the UI on that path so the Run button is never stuck disabled.
    try {
        Invoke-WoscapGuiScan -ScanParameters $splat -OnProgress $onProgress -OnComplete $onComplete -OnError $onError
    } catch {
        Show-WoscapGuiMessage -Text "Could not start scan: $($_.Exception.Message)"
        $Tag['Status'].Text = 'Failed.'
        $Tag['Progress'].Style = 'Continuous'; $Tag['Progress'].Value = 0
        $Tag['Run'].Enabled = $true
    }
}

function Invoke-WoscapGuiExport {
    <#
        The Export action: prompt for a path and write the FULL (unfiltered) result set
        via Export-WoscapResult. NAMED function so it resolves module-private helpers.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    if (@($Tag['Results']).Count -eq 0) { return }
    $fmt = [string]$Tag['Format'].SelectedItem
    $path = Get-WoscapGuiSavePath -Format $fmt
    if (-not $path) { return }
    try {
        Export-WoscapResult -Result @($Tag['Results']) -Format $fmt -Path $path
        Show-WoscapGuiMessage -Text "Exported $(@($Tag['Results']).Count) results to $path"
    } catch {
        Show-WoscapGuiMessage -Text "Export failed: $($_.Exception.Message)"
    }
}

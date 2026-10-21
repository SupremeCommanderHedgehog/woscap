function Show-WoscapGuiMessage {
    <# Thin seam over MessageBox so handlers are testable (mock this in tests). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Text, [string] $Caption = 'woscap')
    [void][System.Windows.Forms.MessageBox]::Show($Text, $Caption)
}

function Set-WoscapGuiStatusTip {
    <# Sets (or, with an empty string, clears) the hover tooltip on the status label --
       the non-modal channel for partial-scan warning detail. Tolerates a tag with no
       StatusTip (older/minimal forms) so callers need no guard. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [string] $Text = '')
    if ($Tag.ContainsKey('StatusTip') -and $Tag['StatusTip']) {
        $Tag['StatusTip'].SetToolTip($Tag['Status'], $Text)
    }
}

function Get-WoscapGuiSavePath {
    <# Thin seam over SaveFileDialog so the Export handler is testable. Returns the
       chosen path, or $null if cancelled. No -Format offers All files only. #>
    [CmdletBinding()]
    param([string] $Format = '')
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    if ($Format) {
        $dlg.Filter = "$Format files|*.$Format|All files|*.*"
        $dlg.DefaultExt = $Format
    } else {
        $dlg.Filter = 'All files|*.*'
    }
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $dlg.FileName } else { $null }
}

function Get-WoscapGuiOpenPath {
    <# Thin seam over OpenFileDialog so handlers are testable. Returns the chosen path(s),
       or an empty array if cancelled. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string] $Filter, [switch] $Multiselect)
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = $Filter
    $dlg.Multiselect = [bool]$Multiselect
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { @($dlg.FileNames) } else { @() }
}

function Get-WoscapGuiFolderPath {
    <# Thin seam over FolderBrowserDialog (mock this in tests); the chosen folder or $null. #>
    [CmdletBinding()]
    param()
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    try {
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $dlg.SelectedPath } else { $null }
    } finally { $dlg.Dispose() }
}

function Invoke-WoscapGuiProfileAdd {
    <# Profiles > Add...: pick one or more .psd1 files and append them. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $paths = @(Get-WoscapGuiOpenPath -Filter 'Profile (*.psd1)|*.psd1|All files|*.*' -Multiselect)
    if ($paths.Count -gt 0) { Add-WoscapGuiProfile -Tag $Tag -Path $paths }
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
    # Rebuilt rows carry no operator selection, whatever WinForms auto-selects.
    $Tag['GridSelectionDeliberate'] = $false
}

function Invoke-WoscapGuiRun {
    <#
        The Run action: validate inputs, build the scan splat, and start the background
        scan. NAMED function -> resolves module-private helpers on any invocation path.
        Stores the tag in $script:WoscapGuiTag so the scan CALLBACKS (plain scriptblocks
        the executor invokes later) can reach the controls. The GUI is single-window, so
        one 'current tag' is safe. Returns $true only if a scan was started.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $script:WoscapGuiTag = $Tag

    $xccdfPath = [string]$Tag['Xccdf'].Text
    if ([string]::IsNullOrWhiteSpace($xccdfPath) -or -not (Test-Path -LiteralPath $xccdfPath)) {
        Show-WoscapGuiMessage -Text 'Select a valid XCCDF (.xml) file before running.'
        return $false
    }
    $benchmark = [string]$Tag['Benchmark'].SelectedItem
    if ([string]::IsNullOrWhiteSpace($benchmark)) {
        Show-WoscapGuiMessage -Text 'Select a benchmark before running. (No content packs were found under Content/.)'
        return $false
    }
    $profiles = @($Tag['Profiles'].Items | ForEach-Object { [string]$_ })
    $missingProfile = @($profiles | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) }) | Select-Object -First 1
    if ($missingProfile) {
        Show-WoscapGuiMessage -Text "Profile not found: $missingProfile"
        return $false
    }
    $contentPath = ([string]$Tag['ContentPath'].Text).Trim()
    if ($contentPath -and -not (Test-Path -LiteralPath $contentPath -PathType Container)) {
        Show-WoscapGuiMessage -Text "Content path not found: $contentPath"
        return $false
    }
    $jsonPath = ([string]$Tag['JsonPath'].Text).Trim()
    if ($jsonPath) {
        $jsonDir = Split-Path -Path $jsonPath -Parent
        if ($jsonDir -and -not (Test-Path -LiteralPath $jsonDir -PathType Container)) {
            Show-WoscapGuiMessage -Text "JSON output folder not found: $jsonDir"
            return $false
        }
    }
    # Credential last: never prompt for one and then reject the run on a bad path.
    $cred = $null
    if ($Tag['UseCred'].Checked) {
        $cred = Get-WoscapGuiCredential
        if (-not $cred) { return $false }   # cancelled
    }
    $splat = ConvertTo-WoscapGuiScanParameter -XccdfPath $xccdfPath `
        -Benchmark $benchmark `
        -Targets   ([string]$Tag['Targets'].Text) `
        -ProfilePath $profiles `
        -Credential $cred `
        -ContentPath $contentPath `
        -ThrottleLimit ([int]$Tag['ThrottleLimit'].Value) `
        -JsonPath $jsonPath

    $Tag['Busy'] = 'Scan'
    Set-WoscapGuiActionEnabled -Tag $Tag -Action Run -Enabled $false
    Set-WoscapGuiActionEnabled -Tag $Tag -Action Remediate -Enabled $false
    $Tag['Status'].Text = 'Scanning...'
    # Remediation must use the pack that produced the results, not the controls at click time.
    $Tag['PendingScanContext'] = @{ Benchmark = $benchmark; ContentPath = $contentPath }

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
        $t['ResultsContext'] = $t['PendingScanContext']
        $t['ResultsStale'] = $false
        Update-WoscapGuiView -Tag $t
        $t['Count'].Text = "$(@($t['Results']).Count) rules"
        Set-WoscapGuiActionEnabled -Tag $t -Action Export -Enabled (@($t['Results']).Count -gt 0)
        Set-WoscapGuiActionEnabled -Tag $t -Action Remediate -Enabled (@($t['Results']).Count -gt 0)
        $t['Progress'].Style = 'Continuous'; $t['Progress'].Value = 0
        $t['Status'].Text = 'Done.'
        # Clear any tooltip left by a prior partial scan; OnWarning re-sets it if needed.
        Set-WoscapGuiStatusTip -Tag $t -Text ''
        $t['Busy'] = $null
        Set-WoscapGuiActionEnabled -Tag $t -Action Run -Enabled $true
    }
    $onWarning = {
        param($Message, $Count)
        # Partial success: results ARE valid and shown. Surface the errors non-modally
        # (status + hover tooltip) instead of a 'Scan failed' dialog.
        # Resolve-WoscapGuiCompletion only classifies Kind='Warning' when Count >= 1.
        $t = $script:WoscapGuiTag
        $n = [int]$Count
        $noun = if ($n -eq 1) { 'warning' } else { 'warnings' }
        $t['Status'].Text = "Done ($n $noun)."
        Set-WoscapGuiStatusTip -Tag $t -Text ([string]$Message)
        Set-WoscapGuiActionEnabled -Tag $t -Action Run -Enabled $true
    }
    $onError = {
        param($Message)
        # A hard failure produced no valid results. Clear any stale rows/tooltip and reset
        # the bar so 'Failed.' is never shown next to leftover data from a previous run
        # (the terminating-error path skips OnComplete, so it never cleaned up).
        $t = $script:WoscapGuiTag
        Show-WoscapGuiMessage -Text "Scan failed: $Message"
        $t['Results'].Clear()
        $t['ResultsContext'] = $null
        Update-WoscapGuiView -Tag $t
        $t['Count'].Text = '0 rules'
        Set-WoscapGuiActionEnabled -Tag $t -Action Export -Enabled $false
        Set-WoscapGuiActionEnabled -Tag $t -Action Remediate -Enabled $false
        $t['Progress'].Style = 'Continuous'; $t['Progress'].Value = 0
        Set-WoscapGuiStatusTip -Tag $t -Text ''
        $t['Status'].Text = 'Failed.'
        $t['Busy'] = $null
        Set-WoscapGuiActionEnabled -Tag $t -Action Run -Enabled $true
    }

    # Starting the background scan can fail synchronously (runspace BeginInvoke or timer
    # Start). Re-enable the UI on that path so the Run button is never stuck disabled.
    try {
        $null = Invoke-WoscapGuiScan -ScanParameters $splat -OnProgress $onProgress `
            -OnComplete $onComplete -OnWarning $onWarning -OnError $onError
    } catch {
        Show-WoscapGuiMessage -Text "Could not start scan: $($_.Exception.Message)"
        $Tag['Status'].Text = 'Failed.'
        $Tag['Progress'].Style = 'Continuous'; $Tag['Progress'].Value = 0
        Set-WoscapGuiActionEnabled -Tag $Tag -Action Remediate -Enabled (@($Tag['Results']).Count -gt 0 -and -not $Tag['ResultsStale'])
        $Tag['Busy'] = $null
        Set-WoscapGuiActionEnabled -Tag $Tag -Action Run -Enabled $true
        return $false
    }
    $true
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

function Set-WoscapGuiContentBusy {
    <#
        One background job at a time: a content job disables every content action and the
        Scan tab's Run/Remediate; going idle restores them under their usual rules.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][bool] $Busy, [string] $Status = '')
    $Tag['ContentBusy'] = $Busy
    Set-WoscapGuiActionEnabled -Tag $Tag -Action ContentDownload -Enabled (-not $Busy)
    Set-WoscapGuiActionEnabled -Tag $Tag -Action ContentUpdate -Enabled (-not $Busy)
    Update-WoscapGuiContentSelection -Tag $Tag
    Set-WoscapGuiActionEnabled -Tag $Tag -Action Run -Enabled (-not $Busy)
    $remediable = @($Tag['Results']).Count -gt 0 -and -not $Tag['ResultsStale'] -and $null -ne $Tag['ResultsContext']
    Set-WoscapGuiActionEnabled -Tag $Tag -Action Remediate -Enabled ((-not $Busy) -and $remediable)
    if ($Status) { $Tag['ContentStatus'].Text = $Status }
}

function Test-WoscapGuiContentIdle {
    <# $true when a content background job may start; Run is disabled only while a scan or remediation runs. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][hashtable] $Tag)
    if ($Tag['ContentBusy']) { return $false }
    if (-not $Tag['Run'].Enabled) {
        Show-WoscapGuiMessage -Text 'A scan or remediation is running; wait for it to finish.'
        return $false
    }
    $true
}

function Get-WoscapGuiContentSelectedRow {
    <# The Get-WoscapBenchmark object of the selected Content grid row, or $null. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $rows = $Tag['ContentGrid'].SelectedRows
    if ($rows.Count -eq 0) { return $null }
    $rows[0].Tag
}

function Save-WoscapGuiDisaTermsChoice {
    <# Persists 'Remember' only after success (the CLI's fail-closed rule); returns a status suffix. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][hashtable] $Job)
    if (-not $Job['Remember']) { return '' }
    try {
        Write-WoscapDisaTermsMarker -CacheRoot (Get-WoscapContentCacheRoot -Destination $Job['Destination'])
        ''
    } catch {
        " (could not remember the DISA terms: $($_.Exception.Message))"
    }
}

function Select-WoscapGuiContentRow {
    <# Selects the grid row whose XCCDF is $Path; the row's Benchmark/Revision is the fallback match. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][string] $Path)
    $grid = $Tag['ContentGrid']
    $revision = Split-Path -Leaf (Split-Path -Parent $Path)
    $benchmark = Split-Path -Leaf (Split-Path -Parent (Split-Path -Parent $Path))
    $match = @($grid.Rows | Where-Object { [string]$_.Tag.Path -eq $Path })
    if ($match.Count -eq 0) {
        $match = @($grid.Rows | Where-Object { [string]$_.Tag.Benchmark -eq $benchmark -and [string]$_.Tag.Revision -eq $revision })
    }
    $grid.ClearSelection()
    if ($match.Count -gt 0) {
        $match[0].Selected = $true
        try { $grid.FirstDisplayedScrollingRowIndex = $match[0].Index } catch { $null = $_ }
    }
    Update-WoscapGuiContentSelection -Tag $Tag
}

function Invoke-WoscapGuiContentDownload {
    <#
        Download action: options dialog, then the DISA terms gate, then Save-WoscapStigContent
        in the background. Never reaches a console prompt: it runs only once the gate proceeds,
        with -AcceptDisaTerms exactly when the gate asked for it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $script:WoscapGuiTag = $Tag
    if (-not (Test-WoscapGuiContentIdle -Tag $Tag)) { return }

    $request = Show-WoscapGuiDownloadDialog
    if ($null -eq $request) { return }
    $destination = Get-WoscapGuiContentDestination -Tag $Tag
    $terms = Resolve-WoscapGuiDisaTerms -CacheRoot (Get-WoscapContentCacheRoot -Destination $destination)
    if (-not $terms.Proceed) {
        $Tag['ContentStatus'].Text = 'Download cancelled.'
        return
    }

    $splat = @{ Benchmark = [string]$request.Benchmark }
    if ($request.Url) { $splat['Url'] = [string]$request.Url }
    if ($request.AllowScrape) { $splat['AllowScrape'] = $true }
    if ($request.Force) { $splat['Force'] = $true }
    if ($destination) { $splat['Destination'] = $destination }
    if ($terms.AcceptSwitch) { $splat['AcceptDisaTerms'] = $true }
    $Tag['ContentJob'] = @{ Benchmark = $splat['Benchmark']; Destination = $destination; Remember = [bool]$terms.Remember }

    Set-WoscapGuiContentBusy -Tag $Tag -Busy $true -Status "Downloading $($splat['Benchmark'])..."

    # Plain scriptblocks reach state via $script:WoscapGuiTag (see Invoke-WoscapGuiRemediate).
    # An errored run is reported once, by OnError; OnSettled handles the rest.
    $onSettled = {
        param($Results, $Outcome)
        $t = $script:WoscapGuiTag
        if ($Outcome.Kind -eq 'Error') { return }
        $job = $t['ContentJob']
        $path = @($Results | Where-Object { $_ -is [string] -and $_ }) | Select-Object -Last 1
        if (-not $path) {
            Show-WoscapGuiMessage -Text "Download of $($job.Benchmark) returned no content."
            Set-WoscapGuiContentBusy -Tag $t -Busy $false -Status 'Download failed.'
            return
        }
        $note = Save-WoscapGuiDisaTermsChoice -Job $job
        Set-WoscapGuiContentBusy -Tag $t -Busy $false
        # The new revision must be visible to be selected.
        $filter = $t['ContentFilter']
        if ([string]$filter.SelectedItem -notin @('All', $job.Benchmark) -and $filter.Items.Contains('All')) {
            $t['ContentRefreshing'] = $true
            try { $filter.SelectedItem = 'All' } finally { $t['ContentRefreshing'] = $false }
        }
        Update-WoscapGuiContentView -Tag $t
        Select-WoscapGuiContentRow -Tag $t -Path $path
        $t['ContentStatus'].Text = "Downloaded $($job.Benchmark) to $path$note"
    }
    $onError = {
        param($Message)
        $t = $script:WoscapGuiTag
        Show-WoscapGuiMessage -Text "Download failed: $Message"
        Set-WoscapGuiContentBusy -Tag $t -Busy $false -Status 'Download failed.'
    }

    try {
        Invoke-WoscapGuiScan -Command 'Save-WoscapStigContent' -ScanParameters $splat -OnSettled $onSettled -OnError $onError
    } catch {
        Show-WoscapGuiMessage -Text "Could not start the download: $($_.Exception.Message)"
        Set-WoscapGuiContentBusy -Tag $Tag -Busy $false -Status 'Download failed.'
    }
}

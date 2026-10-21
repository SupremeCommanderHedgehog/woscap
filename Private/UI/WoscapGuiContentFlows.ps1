function Set-WoscapGuiContentBusy {
    <#
        One background job at a time: a content job disables every content action and the
        Scan tab's Run/Remediate; going idle restores them under their usual rules.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][bool] $Busy, [string] $Status = '')
    $Tag['Busy'] = if ($Busy) { 'Content' } else { $null }
    Set-WoscapGuiActionEnabled -Tag $Tag -Action ContentDownload -Enabled (-not $Busy)
    Set-WoscapGuiActionEnabled -Tag $Tag -Action ContentUpdate -Enabled (-not $Busy)
    Update-WoscapGuiContentSelection -Tag $Tag
    Set-WoscapGuiActionEnabled -Tag $Tag -Action Run -Enabled (-not $Busy)
    $remediable = @($Tag['Results']).Count -gt 0 -and -not $Tag['ResultsStale'] -and $null -ne $Tag['ResultsContext']
    Set-WoscapGuiActionEnabled -Tag $Tag -Action Remediate -Enabled ((-not $Busy) -and $remediable)
    if ($Status) { $Tag['ContentStatus'].Text = $Status }
}

function Test-WoscapGuiContentIdle {
    <# $true when no scan, remediation or content job is in flight (Tag 'Busy'); otherwise says so. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $busy = [string]$Tag['Busy']
    if (-not $busy) { return $true }
    $what = switch ($busy) { 'Scan' { 'A scan' } 'Remediation' { 'A remediation' } default { 'A content download or update' } }
    Show-WoscapGuiMessage -Text "$what is running; wait for it to finish."
    $false
}

function Get-WoscapGuiContentTarget {
    <#
        @{ Destination; Root } for a content action, or $null (after a message) when the Cache
        folder no longer names the root the grid was listed from: rows must never be acted on
        against a different cache.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $destination = Get-WoscapGuiContentDestination -Tag $Tag
    try {
        $root = Get-WoscapContentCacheRoot -Destination $destination
    } catch {
        Show-WoscapGuiMessage -Text "Cache folder is not a valid path: $($_.Exception.Message)"
        return $null
    }
    $listed = [string]$Tag['ContentListedRoot']
    if ($listed -and $root -ne $listed) {
        Show-WoscapGuiMessage -Text "The Cache folder changed since the list was shown ($listed). Click Refresh first."
        return $null
    }
    @{ Destination = $destination; Root = $root }
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
    $target = Get-WoscapGuiContentTarget -Tag $Tag
    if (-not $target) { return }

    $request = Show-WoscapGuiDownloadDialog
    if ($null -eq $request) { return }
    $destination = $target.Destination
    $terms = Resolve-WoscapGuiDisaTerms -CacheRoot $target.Root
    if ($terms['Error']) {
        Show-WoscapGuiMessage -Text "Could not show the DISA terms: $($terms['Error'])"
        $Tag['ContentStatus'].Text = 'Download not started.'
        return
    }
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
    $Tag['ContentJob'] = @{ Benchmark = $splat['Benchmark']; Destination = $destination; Remember = [bool]$terms.Remember; Succeeded = $false }

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
        $job['Succeeded'] = $true
        $note = Save-WoscapGuiDisaTermsChoice -Job $job
        Set-WoscapGuiContentBusy -Tag $t -Busy $false
        # The new revision must be visible to be selected.
        $filter = $t['ContentFilter']
        if ([string]$filter.SelectedItem -notin @('All', $job.Benchmark) -and $filter.Items.Contains('All')) {
            $t['ContentRefreshing'] = $true
            try { $filter.SelectedItem = 'All' } finally { $t['ContentRefreshing'] = $false }
        }
        # The job's root, not the Cache folder box, which may have been edited meanwhile.
        Update-WoscapGuiContentView -Tag $t -Destination $job.Destination
        Select-WoscapGuiContentRow -Tag $t -Path $path
        $t['ContentStatus'].Text = "Downloaded $($job.Benchmark) to $path$note"
    }
    # Also reached when OnSettled itself throws (the runner's tick catch).
    $onError = {
        param($Message)
        $t = $script:WoscapGuiTag
        if ($t['ContentJob']['Succeeded']) {
            Show-WoscapGuiMessage -Text "Download completed, but a follow-up step failed: $Message"
            Set-WoscapGuiContentBusy -Tag $t -Busy $false -Status 'Download completed; a follow-up step failed.'
            return
        }
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

function Invoke-WoscapGuiContentUpdate {
    <#
        Update action: scope (selected benchmark, else every cached one) and options, a
        background -WhatIf preview (no network), the confirmation dialog, the DISA terms gate,
        then the real run with -Confirm:$false. Cancel at any step updates nothing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $script:WoscapGuiTag = $Tag
    if (-not (Test-WoscapGuiContentIdle -Tag $Tag)) { return }
    $target = Get-WoscapGuiContentTarget -Tag $Tag
    if (-not $target) { return }

    $row = Get-WoscapGuiContentSelectedRow -Tag $Tag
    $benchmark = if ($row) { [string](Get-WoscapObjectProperty $row 'Benchmark' '') } else { '' }
    $options = Show-WoscapGuiUpdateDialog -Benchmark $benchmark
    if ($null -eq $options) { return }

    $destination = $target.Destination
    $base = @{}
    if ($benchmark) {
        $base['Benchmark'] = $benchmark
        # Update-WoscapBenchmark rejects -Url without a single -Benchmark.
        if ($options.Url) { $base['Url'] = [string]$options.Url }
    }
    if ($options.AllowScrape) { $base['AllowScrape'] = $true }
    if ($destination) { $base['Destination'] = $destination }
    $Tag['ContentJob'] = @{ Base = $base; Destination = $destination; Root = $target.Root; Remember = $false; Succeeded = $false }

    $preview = $base.Clone()
    $preview['WhatIf'] = $true

    Set-WoscapGuiContentBusy -Tag $Tag -Busy $true -Status 'Checking which benchmarks would update...'

    $onPreview = {
        param($Results, $Outcome)
        $t = $script:WoscapGuiTag
        if ($Outcome.Kind -eq 'Error') { return }
        $rows = @($Results)
        if ($rows.Count -eq 0) {
            Set-WoscapGuiContentBusy -Tag $t -Busy $false -Status 'Nothing to update.'
            return
        }
        if (-not (Show-WoscapGuiUpdateConfirmDialog -Rows $rows)) {
            Set-WoscapGuiContentBusy -Tag $t -Busy $false -Status 'Update cancelled.'
            return
        }
        $job = $t['ContentJob']
        $terms = Resolve-WoscapGuiDisaTerms -CacheRoot $job.Root
        if ($terms['Error']) {
            Show-WoscapGuiMessage -Text "Could not show the DISA terms: $($terms['Error'])"
            Set-WoscapGuiContentBusy -Tag $t -Busy $false -Status 'Update not started.'
            return
        }
        if (-not $terms.Proceed) {
            Set-WoscapGuiContentBusy -Tag $t -Busy $false -Status 'Update cancelled.'
            return
        }
        Start-WoscapGuiContentUpdateApply -Tag $t -AcceptDisaTerms ([bool]$terms.AcceptSwitch) -Remember ([bool]$terms.Remember)
    }
    $onError = {
        param($Message)
        $t = $script:WoscapGuiTag
        Show-WoscapGuiMessage -Text "Update failed: $Message"
        Set-WoscapGuiContentBusy -Tag $t -Busy $false -Status 'Update failed.'
    }

    try {
        Invoke-WoscapGuiScan -Command 'Update-WoscapBenchmark' -ScanParameters $preview -OnSettled $onPreview -OnError $onError
    } catch {
        Show-WoscapGuiMessage -Text "Could not start the update: $($_.Exception.Message)"
        Set-WoscapGuiContentBusy -Tag $Tag -Busy $false -Status 'Update failed.'
    }
}

function Start-WoscapGuiContentUpdateApply {
    <# The confirmed run: -Confirm:$false stands in for the console prompt the dialog already answered. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [bool] $AcceptDisaTerms, [bool] $Remember)
    $job = $Tag['ContentJob']
    $job['Remember'] = $Remember
    $real = $job.Base.Clone()
    $real['Confirm'] = $false
    if ($AcceptDisaTerms) { $real['AcceptDisaTerms'] = $true }
    $Tag['ContentStatus'].Text = 'Updating...'

    $onApplied = {
        param($Results, $Outcome)
        $t = $script:WoscapGuiTag
        if ($Outcome.Kind -eq 'Error') { return }
        $job = $t['ContentJob']
        $job['Succeeded'] = $true
        $rows = @($Results)
        $count = { param($s) @($rows | Where-Object { [string](Get-WoscapObjectProperty $_ 'Status' '') -eq $s }).Count }
        $updated = & $count 'Updated'; $current = & $count 'AlreadyCurrent'; $failed = & $count 'Failed'
        # Update reports per-benchmark failures as rows, so success means at least one benchmark got through.
        $note = if ($updated + $current -gt 0) { Save-WoscapGuiDisaTermsChoice -Job $job } else { '' }
        Set-WoscapGuiContentBusy -Tag $t -Busy $false
        Update-WoscapGuiContentView -Tag $t -Destination $job.Destination
        $t['ContentStatus'].Text = "Update done: $updated updated, $current already current, $failed failed.$note"
        Show-WoscapGuiUpdateReport -Result $rows
    }
    # Also reached when OnSettled itself throws (the runner's tick catch).
    $onError = {
        param($Message)
        $t = $script:WoscapGuiTag
        $job = $t['ContentJob']
        $text = if ($job['Succeeded']) { "Update completed, but a follow-up step failed: $Message" } else { "Update failed: $Message" }
        Show-WoscapGuiMessage -Text $text
        Set-WoscapGuiContentBusy -Tag $t -Busy $false
        Update-WoscapGuiContentView -Tag $t -Destination $job.Destination
        $t['ContentStatus'].Text = if ($job['Succeeded']) { 'Update completed; a follow-up step failed.' } else { 'Update failed.' }
    }

    try {
        Invoke-WoscapGuiScan -Command 'Update-WoscapBenchmark' -ScanParameters $real -OnSettled $onApplied -OnError $onError
    } catch {
        Show-WoscapGuiMessage -Text "Could not start the update: $($_.Exception.Message)"
        Set-WoscapGuiContentBusy -Tag $Tag -Busy $false -Status 'Update failed.'
    }
}

function Invoke-WoscapGuiContentRemove {
    <#
        Remove action: the Remove dialog picks this revision or every revision; then
        Remove-WoscapBenchmark runs on the UI thread (local and fast) with -Confirm:$false,
        which stands in for the console prompt the dialog already answered.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $script:WoscapGuiTag = $Tag
    if (-not (Test-WoscapGuiContentIdle -Tag $Tag)) { return }
    $row = Get-WoscapGuiContentSelectedRow -Tag $Tag
    if (-not $row) { return }
    $target = Get-WoscapGuiContentTarget -Tag $Tag
    if (-not $target) { return }

    $destination = $target.Destination
    $root = $target.Root
    $choice = Show-WoscapGuiRemoveDialog -Benchmark ([string](Get-WoscapObjectProperty $row 'Benchmark' '')) `
        -Revision ([string](Get-WoscapObjectProperty $row 'Revision' '')) -CacheRoot $root
    if ($null -eq $choice) { return }

    try {
        $splat = Get-WoscapGuiRemoveScope -Row $row -AllRevisions:([bool]$choice.AllRevisions)
        $what = if ($splat.ContainsKey('Revision')) { "$($splat.Benchmark) $($splat.Revision)" } else { "all revisions of $($splat.Benchmark)" }
        $splat['Confirm'] = $false
        if ($destination) { $splat['Destination'] = $destination }
        $removed = @(Remove-WoscapBenchmark @splat -ErrorAction Stop -WarningAction SilentlyContinue)
    } catch {
        Show-WoscapGuiMessage -Text "Remove failed: $($_.Exception.Message)"
        Update-WoscapGuiContentView -Tag $Tag
        $Tag['ContentStatus'].Text = 'Remove failed.'
        return
    }
    Update-WoscapGuiContentView -Tag $Tag
    $Tag['ContentStatus'].Text = if ($removed.Count -gt 0) { "Removed $what from $root." } else { "Nothing to remove for $what in $root." }
}

function Invoke-WoscapGuiContentUseForScan {
    <#
        Use for scan: hands the selected revision's XCCDF to the Scan tab and selects the
        matching content pack; without one, warns that results would be Not_Reviewed.
        Never starts a scan.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    if (-not (Test-WoscapGuiContentIdle -Tag $Tag)) { return }
    $row = Get-WoscapGuiContentSelectedRow -Tag $Tag
    if (-not $row) { return }
    if (-not (Get-WoscapGuiContentTarget -Tag $Tag)) { return }
    $benchmark = [string](Get-WoscapObjectProperty $row 'Benchmark' '')
    $Tag['Xccdf'].Text = [string](Get-WoscapObjectProperty $row 'Path' '')
    $pack = Find-WoscapGuiContentPack -Benchmark $benchmark -Available @($Tag['Benchmark'].Items | ForEach-Object { [string]$_ })
    if ($pack) {
        $Tag['Benchmark'].SelectedItem = $pack
        $Tag['Status'].Text = "Ready to scan with $benchmark $([string](Get-WoscapObjectProperty $row 'Revision' ''))."
    } else {
        # A stale pack must not pair with this XCCDF; Run's validation then asks for one.
        $Tag['Benchmark'].SelectedIndex = -1
        $Tag['Status'].Text = "No content pack for '$benchmark'; results would be Not_Reviewed."
    }
    $Tag['Tabs'].SelectedTab = $Tag['ScanTab']
}

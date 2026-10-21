function Read-WoscapGuiIntegrationConfig {
    <# The config form for -Hook on the target plugin: its typed hashtable, or $null on cancel or an unreadable schema. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Target, [Parameter(Mandatory)][string] $Hook, [Parameter(Mandatory)][string] $Title)
    try {
        $options = Get-WoscapGuiConfigOptions -Plugin $Target.Plugin -Hook $Hook
    } catch {
        Show-WoscapGuiMessage -Text "Could not read the options of '$($Target.Name)': $($_.Exception.Message)"
        return $null
    }
    Show-WoscapGuiConfigForm -Options $options -Title $Title
}

function New-WoscapGuiIntegrationSplat {
    <# Integration + the form's own Config hashtable (never copied) + PluginPath when a Plugin folder is set. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][hashtable] $Target, [Parameter(Mandatory)][hashtable] $Config)
    $p = @{ Integration = [string]$Target.Name; Config = $Config }
    if ($Target.PluginPath) { $p['PluginPath'] = [string]$Target.PluginPath }
    $p
}

function Test-WoscapGuiIntegrationResults {
    <# $true when the Scan tab holds results; otherwise says why -What needs them. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][string] $What)
    if (@($Tag['Results']).Count -gt 0) { return $true }
    Show-WoscapGuiMessage -Text "There are no current scan results to $What. Run a scan on the Scan tab first."
    $false
}

function Start-WoscapGuiIntegrationJob {
    <#
        Runs an integration cmdlet in the background with Busy = 'Integration'. -Job describes
        the action (Kind, Action, Name, ...) for Complete-WoscapGuiIntegrationJob. Busy is
        restored on success, error and a failed start; once the cmdlet succeeded, a later
        failure is reported as "completed, but a follow-up step failed".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable] $Tag,
        [Parameter(Mandatory)][ValidateSet('Import-WoscapIntegration', 'Invoke-WoscapIntegration', 'Export-WoscapIntegration')][string] $Command,
        [Parameter(Mandatory)][hashtable] $Parameters,
        [Parameter(Mandatory)][hashtable] $Job,
        [Parameter(Mandatory)][string] $Status
    )
    $Job['Succeeded'] = $false
    $Tag['IntegrationJob'] = $Job
    Set-WoscapGuiIntegrationBusy -Tag $Tag -Busy $true -Status $Status

    # Plain scriptblocks reach state via $script:WoscapGuiTag (see Invoke-WoscapGuiRemediate).
    # An errored run is reported once, by OnError; OnSettled handles the rest.
    $onSettled = {
        param($Results, $Outcome)
        $t = $script:WoscapGuiTag
        if ($Outcome.Kind -eq 'Error') { return }
        $job = $t['IntegrationJob']
        $job['Succeeded'] = $true
        $job['Warnings'] = if ($Outcome.Kind -eq 'Warning') { [int]$Outcome.Count } else { 0 }
        Set-WoscapGuiIntegrationBusy -Tag $t -Busy $false
        Complete-WoscapGuiIntegrationJob -Tag $t -Results @($Results)
    }
    # Also reached when OnSettled itself throws (the runner's tick catch).
    $onError = {
        param($Message)
        $t = $script:WoscapGuiTag
        $job = $t['IntegrationJob']
        Set-WoscapGuiIntegrationBusy -Tag $t -Busy $false
        if ($job['Succeeded']) {
            $t['IntegrationStatus'].Text = "$($job.Action) completed; a follow-up step failed."
            Show-WoscapGuiMessage -Text "$($job.Action) completed, but a follow-up step failed: $Message"
            return
        }
        $t['IntegrationStatus'].Text = "$($job.Action) failed."
        Show-WoscapGuiMessage -Text "$($job.Action) failed: $Message"
    }

    try {
        Invoke-WoscapGuiScan -Command $Command -ScanParameters $Parameters -OnSettled $onSettled -OnError $onError
    } catch {
        Set-WoscapGuiIntegrationBusy -Tag $Tag -Busy $false -Status "$($Job.Action) failed."
        Show-WoscapGuiMessage -Text "Could not start $($Job.Action.ToLowerInvariant()): $($_.Exception.Message)"
    }
}

function Complete-WoscapGuiIntegrationJob {
    <# Follow-up for a finished integration job, by its Kind. Nothing here starts a scan. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]] $Results)
    $job = $Tag['IntegrationJob']
    $name = [string]$job.Name
    $note = if ($job['Warnings'] -gt 0) { " ($($job['Warnings']) warning(s))" } else { '' }
    switch ([string]$job.Kind) {
        'Targets' {
            $hosts = @($Results | Where-Object { $null -ne $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
            if ($hosts.Count -eq 0) {
                $Tag['IntegrationStatus'].Text = "No targets imported from $name.$note"
                Show-WoscapGuiMessage -Text "$name returned no targets; Scan Targets is unchanged."
                return
            }
            Set-WoscapGuiIntegrationTargets -Tag $Tag -Hosts $hosts
            $text = "Imported $($hosts.Count) target(s) from $name.$note"
            $Tag['IntegrationStatus'].Text = $text
            $Tag['Status'].Text = "$text Review them, then Run."
        }
        { $_ -in 'Findings', 'ExternalScan' } {
            $links = $null
            $found = @($Results)
            if ($job['Correlated']) {
                $joined = $found | Select-Object -Last 1
                $found = @(Get-WoscapObjectProperty $joined 'Findings' @())
                $links = @(Get-WoscapObjectProperty $joined 'Links' @())
            }
            $verb = if ($job.Kind -eq 'Findings') { "Imported $($found.Count) finding(s) from $name" }
                else { "External scan by $name returned $($found.Count) finding(s)" }
            $linked = if ($null -ne $links) { ", $($links.Count) link(s) to scan results" } else { '' }
            $Tag['IntegrationStatus'].Text = "$verb$linked.$note"
            Show-WoscapGuiIntegrationFindings -Title "$($job.Action) - $name" -Findings $found -Links $links
        }
        'ExportFindings' {
            $values = @($Results)
            # A plugin that returns only $false is saying the export did not go through.
            $failed = $values.Count -gt 0 -and @($values | Where-Object { $_ -is [bool] -and -not $_ }).Count -eq $values.Count
            $summary = Format-WoscapGuiIntegrationReturn -Value $values
            if ($failed) {
                $Tag['IntegrationStatus'].Text = "$name reported that the export did not succeed.$note"
                Show-WoscapGuiMessage -Text "$name reported that the export did not succeed. Check the integration options and its log."
                return
            }
            $Tag['IntegrationStatus'].Text = "Exported $($job.Count) result(s) to $name.$note"
            Show-WoscapGuiMessage -Text "Exported $($job.Count) result(s) to $name.$note`r`n$summary"
        }
        'Remediation' {
            $path = @($Results | Where-Object { $_ -is [string] -and $_ }) | Select-Object -Last 1
            if (-not $path) { $path = [string]$job.Path }
            $Tag['IntegrationStatus'].Text = "Remediation written to $path$note"
            Show-WoscapGuiMessage -Text "$name wrote the remediation for $($job.Count) result(s) to $path$note"
        }
    }
}

function Set-WoscapGuiIntegrationTargets {
    <# Writes exactly -Hosts into Scan Targets (comma-separated) and shows the Scan tab; never runs a scan. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][string[]] $Hosts)
    $Tag['Targets'].Text = $Hosts -join ', '
    $Tag['Tabs'].SelectedTab = $Tag['ScanTab']
}

function Invoke-WoscapGuiIntegrationImportTargets {
    <#
        Import targets: source file (optional), the Get-Targets options, then
        Import-WoscapIntegration -Targets in the background; the hosts land in Scan Targets.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $script:WoscapGuiTag = $Tag
    if (-not (Test-WoscapGuiContentIdle -Tag $Tag)) { return }
    $target = Get-WoscapGuiIntegrationTarget -Tag $Tag -Hook 'Get-Targets'
    if (-not $target) { return }
    $source = Show-WoscapGuiIntegrationSourceDialog -Mode Targets -Integration $target.Name
    if ($null -eq $source) { return }
    $config = Read-WoscapGuiIntegrationConfig -Target $target -Hook 'Get-Targets' -Title "Import targets - $($target.Name)"
    if ($null -eq $config) { return }

    $p = New-WoscapGuiIntegrationSplat -Target $target -Config $config
    $p['Targets'] = $true
    if ($source.Path) { $p['Source'] = [string]$source.Path }
    Start-WoscapGuiIntegrationJob -Tag $Tag -Command 'Import-WoscapIntegration' -Parameters $p `
        -Job @{ Kind = 'Targets'; Action = 'Import targets'; Name = $target.Name } -Status "Importing targets from $($target.Name)..."
}

function Invoke-WoscapGuiIntegrationImportFindings {
    <#
        Import findings: report file and the Correlate choice, the Import-Findings options,
        then Import-WoscapIntegration -Findings in the background (-CorrelateWith = the current
        scan results only when ticked); the findings dialog shows the outcome.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $script:WoscapGuiTag = $Tag
    if (-not (Test-WoscapGuiContentIdle -Tag $Tag)) { return }
    $target = Get-WoscapGuiIntegrationTarget -Tag $Tag -Hook 'Import-Findings'
    if (-not $target) { return }
    $results = @($Tag['Results'])
    $source = Show-WoscapGuiIntegrationSourceDialog -Mode Findings -Integration $target.Name -CanCorrelate:($results.Count -gt 0)
    if ($null -eq $source) { return }
    if ($source.Correlate -and -not (Test-WoscapGuiIntegrationResults -Tag $Tag -What 'correlate with')) { return }
    $config = Read-WoscapGuiIntegrationConfig -Target $target -Hook 'Import-Findings' -Title "Import findings - $($target.Name)"
    if ($null -eq $config) { return }

    $p = New-WoscapGuiIntegrationSplat -Target $target -Config $config
    $p['Findings'] = $true
    $p['Path'] = [string]$source.Path
    if ($source.Correlate) { $p['CorrelateWith'] = $results }
    Start-WoscapGuiIntegrationJob -Tag $Tag -Command 'Import-WoscapIntegration' -Parameters $p `
        -Job @{ Kind = 'Findings'; Action = 'Import findings'; Name = $target.Name; Correlated = [bool]$source.Correlate } `
        -Status "Importing findings from $($target.Name)..."
}

function Invoke-WoscapGuiIntegrationRunScan {
    <# Run external scan: the Invoke-ExternalScan options, then Invoke-WoscapIntegration in the background; the findings dialog shows the outcome. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $script:WoscapGuiTag = $Tag
    if (-not (Test-WoscapGuiContentIdle -Tag $Tag)) { return }
    $target = Get-WoscapGuiIntegrationTarget -Tag $Tag -Hook 'Invoke-ExternalScan'
    if (-not $target) { return }
    $config = Read-WoscapGuiIntegrationConfig -Target $target -Hook 'Invoke-ExternalScan' -Title "Run external scan - $($target.Name)"
    if ($null -eq $config) { return }

    $p = New-WoscapGuiIntegrationSplat -Target $target -Config $config
    Start-WoscapGuiIntegrationJob -Tag $Tag -Command 'Invoke-WoscapIntegration' -Parameters $p `
        -Job @{ Kind = 'ExternalScan'; Action = 'External scan'; Name = $target.Name } -Status "External scan by $($target.Name) running..."
}

function Invoke-WoscapGuiIntegrationExportFindings {
    <# Export findings: refuses without scan results; the Export-Findings options, then Export-WoscapIntegration with exactly the current results. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $script:WoscapGuiTag = $Tag
    if (-not (Test-WoscapGuiContentIdle -Tag $Tag)) { return }
    if (-not (Test-WoscapGuiIntegrationResults -Tag $Tag -What 'export')) { return }
    $target = Get-WoscapGuiIntegrationTarget -Tag $Tag -Hook 'Export-Findings'
    if (-not $target) { return }
    $config = Read-WoscapGuiIntegrationConfig -Target $target -Hook 'Export-Findings' -Title "Export findings - $($target.Name)"
    if ($null -eq $config) { return }

    $results = @($Tag['Results'])
    $p = New-WoscapGuiIntegrationSplat -Target $target -Config $config
    $p['Result'] = $results
    Start-WoscapGuiIntegrationJob -Tag $Tag -Command 'Export-WoscapIntegration' -Parameters $p `
        -Job @{ Kind = 'ExportFindings'; Action = 'Export findings'; Name = $target.Name; Count = $results.Count } `
        -Status "Exporting $($results.Count) result(s) to $($target.Name)..."
}

function Invoke-WoscapGuiIntegrationExportRemediation {
    <#
        Export remediation: refuses without scan results; the New-Remediation options and a
        save path, then Export-WoscapIntegration -Remediation in the background (plugin code
        writes the file); the written path is shown.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $script:WoscapGuiTag = $Tag
    if (-not (Test-WoscapGuiContentIdle -Tag $Tag)) { return }
    if (-not (Test-WoscapGuiIntegrationResults -Tag $Tag -What 'export remediation for')) { return }
    $target = Get-WoscapGuiIntegrationTarget -Tag $Tag -Hook 'New-Remediation'
    if (-not $target) { return }
    $config = Read-WoscapGuiIntegrationConfig -Target $target -Hook 'New-Remediation' -Title "Export remediation - $($target.Name)"
    if ($null -eq $config) { return }
    $path = Get-WoscapGuiSavePath -Format 'yml'
    if (-not $path) { return }

    $results = @($Tag['Results'])
    $p = New-WoscapGuiIntegrationSplat -Target $target -Config $config
    $p['Remediation'] = $true
    $p['Path'] = [string]$path
    $p['Result'] = $results
    Start-WoscapGuiIntegrationJob -Tag $Tag -Command 'Export-WoscapIntegration' -Parameters $p `
        -Job @{ Kind = 'Remediation'; Action = 'Export remediation'; Name = $target.Name; Count = $results.Count; Path = [string]$path } `
        -Status "Writing remediation with $($target.Name)..."
}

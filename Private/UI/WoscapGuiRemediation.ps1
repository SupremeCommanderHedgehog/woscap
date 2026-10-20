function Set-WoscapGuiRemediationBusy {
    <# Run and Remediate are mutually exclusive with an in-flight remediation. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][bool] $Busy, [string] $Status = '')
    Set-WoscapGuiActionEnabled -Tag $Tag -Action Run -Enabled (-not $Busy)
    Set-WoscapGuiActionEnabled -Tag $Tag -Action Remediate -Enabled ((-not $Busy) -and @($Tag['Results']).Count -gt 0)
    $Tag['Progress'].Style = if ($Busy) { 'Marquee' } else { 'Continuous' }
    if ($Status) { $Tag['Status'].Text = $Status }
}

function Get-WoscapGuiRemediationFailureText {
    <# Once apply results are delivered the system has changed; never call a later failure 'Remediation failed'. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][hashtable] $Tag, [string] $Message = '', [string] $Default = 'Remediation failed')
    if ($Tag['RemediationDelivered']) {
        "Fixes were already applied, but a follow-up step failed: $Message"
    } else {
        "${Default}: $Message"
    }
}

function Invoke-WoscapGuiRemediate {
    <#
        Remediate action: pick local Open findings (deliberate selection, else every
        visible row) using the pack of the scan that produced them, preview them
        with -WhatIf in the background, let the operator untick fixes, apply exactly the
        ticked findings with -Force, then show the report and offer a re-scan. -Force only
        replaces the console ShouldProcess prompt, which the confirmation dialog stands in for.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $script:WoscapGuiTag = $Tag

    $context = $Tag['ResultsContext']
    if (-not $context) {
        Show-WoscapGuiMessage -Text 'Run a scan before remediating.'
        return
    }
    $selected = @(if ($Tag['GridSelectionDeliberate']) { Get-WoscapGuiSelectedResult -Grid $Tag['Grid'] })
    $target = Select-WoscapGuiRemediationTarget -Result @(Get-WoscapGuiVisibleResult -Grid $Tag['Grid']) -Selected $selected
    if (@($target.Findings).Count -eq 0) {
        Show-WoscapGuiMessage -Text ("No Open findings for this computer to remediate ({0} remote, {1} not Open)." -f `
            $target.SkippedRemote, $target.SkippedNotOpen)
        return
    }

    $base = @{ Benchmark = [string]$context.Benchmark; Quiet = $true }
    if ($context.ContentPath) { $base['ContentPath'] = [string]$context.ContentPath }
    $Tag['RemediationBase'] = $base
    $Tag['RemediationTarget'] = $target
    $Tag['RemediationRescan'] = $false
    $Tag['RemediationDelivered'] = $false

    $preview = $base.Clone()
    $preview['Result'] = @($target.Findings)
    $preview['WhatIf'] = $true

    Set-WoscapGuiRemediationBusy -Tag $Tag -Busy $true -Status 'Planning remediation...'

    # Plain scriptblocks (not closures) keep module session state; state is reached via
    # $script:WoscapGuiTag, as in Invoke-WoscapGuiRun.
    $onPreview = {
        param($Results)
        $t = $script:WoscapGuiTag
        if (@($Results).Count -eq 0) {
            Set-WoscapGuiRemediationBusy -Tag $t -Busy $false -Status 'Nothing to remediate.'
            return
        }
        $tg = $t['RemediationTarget']
        $notes = @()
        if ($tg.SkippedRemote -gt 0)  { $notes += "$($tg.SkippedRemote) remote finding(s) skipped." }
        if ($tg.SkippedNotOpen -gt 0) { $notes += "$($tg.SkippedNotOpen) finding(s) not Open skipped." }
        $ids = @(Show-WoscapGuiRemediationDialog -Plan @($Results) -Summary ($notes -join ' ') -Elevated (Test-WoscapGuiElevated))
        if ($ids.Count -eq 0) {
            Set-WoscapGuiRemediationBusy -Tag $t -Busy $false -Status 'Remediation cancelled.'
            return
        }
        Start-WoscapGuiRemediationApply -Tag $t -StigId $ids
    }
    $onError = {
        param($Message)
        $t = $script:WoscapGuiTag
        Show-WoscapGuiMessage -Text "Remediation failed: $Message"
        Set-WoscapGuiRemediationBusy -Tag $t -Busy $false -Status 'Remediation failed.'
    }

    try {
        Invoke-WoscapGuiScan -Command 'Invoke-WoscapRemediation' -ScanParameters $preview `
            -OnComplete $onPreview -OnError $onError
    } catch {
        Show-WoscapGuiMessage -Text "Could not start remediation: $($_.Exception.Message)"
        Set-WoscapGuiRemediationBusy -Tag $Tag -Busy $false -Status 'Failed.'
    }
}

function Start-WoscapGuiRemediationApply {
    <# Applies only the findings named by the ticked rows, then shows the report. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][string[]] $StigId)
    $subset = @($Tag['RemediationTarget'].Findings | Where-Object {
        [string](Get-WoscapObjectProperty $_ 'StigId' '') -in $StigId
    })
    $apply = $Tag['RemediationBase'].Clone()
    $apply['Result'] = $subset
    $apply['Force'] = $true
    $Tag['Status'].Text = 'Applying fixes...'

    $onApplied = {
        param($Results)
        $t = $script:WoscapGuiTag
        $t['RemediationDelivered'] = @($Results).Count -gt 0
        Set-WoscapGuiRemediationBusy -Tag $t -Busy $false -Status 'Remediation done.'
        if ((Show-WoscapGuiRemediationReport -Result @($Results)) -eq 'Rescan') {
            $t['RemediationRescan'] = $true
            Invoke-WoscapGuiRun -Tag $t
        }
    }
    # The runner classifies the outcome AFTER OnComplete; once the re-scan owns the UI,
    # a late apply outcome must not touch the status line or re-enable Run.
    $onWarning = {
        param($Message, $Count)
        $t = $script:WoscapGuiTag
        if ($t['RemediationRescan']) { return }
        $t['Status'].Text = "Remediation done ($Count warning(s))."
        Set-WoscapGuiStatusTip -Tag $t -Text ([string]$Message)
    }
    $onError = {
        param($Message)
        $t = $script:WoscapGuiTag
        Show-WoscapGuiMessage -Text (Get-WoscapGuiRemediationFailureText -Tag $t -Message $Message)
        if ($t['RemediationRescan']) { return }
        Set-WoscapGuiRemediationBusy -Tag $t -Busy $false -Status 'Remediation failed.'
    }

    try {
        Invoke-WoscapGuiScan -Command 'Invoke-WoscapRemediation' -ScanParameters $apply `
            -OnComplete $onApplied -OnWarning $onWarning -OnError $onError
    } catch {
        Show-WoscapGuiMessage -Text (Get-WoscapGuiRemediationFailureText -Tag $Tag -Message $_.Exception.Message -Default 'Could not start remediation')
        if ($Tag['RemediationRescan']) { return }
        Set-WoscapGuiRemediationBusy -Tag $Tag -Busy $false -Status 'Failed.'
    }
}

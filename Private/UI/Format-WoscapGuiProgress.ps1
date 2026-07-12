function Format-WoscapGuiProgress {
    <#
        Pure helper: maps a PowerShell ProgressRecord to the values the GUI needs to
        update its progress bar/label. A negative PercentComplete (no known total)
        means 'indeterminate' (marquee). A negative percent is clamped to 0; the
        ProgressRecord type itself enforces the <=100 upper bound.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.Management.Automation.ProgressRecord] $Record
    )
    $pct = [int]$Record.PercentComplete
    $indeterminate = ($pct -lt 0)
    if ($indeterminate) { $pct = 0 }

    $text = if ([string]::IsNullOrWhiteSpace($Record.StatusDescription)) {
        $Record.Activity
    } else {
        $Record.StatusDescription
    }

    [pscustomobject]@{ Percent = $pct; Text = $text; Indeterminate = $indeterminate }
}

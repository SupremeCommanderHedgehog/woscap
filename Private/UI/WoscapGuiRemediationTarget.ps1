function Select-WoscapGuiRemediationTarget {
    <#
        Pure: picks the findings the GUI may remediate. Base set is the selection when
        there is one, else every result. Invoke-WoscapRemediation only touches the LOCAL
        host, so rows from other hosts are skipped (never "fixed" here on a remote's
        evidence), as are rows that are not Open. Returns @{ Findings; SkippedRemote;
        SkippedNotOpen }.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [AllowEmptyCollection()] [object[]] $Result = @(),
        [AllowEmptyCollection()] [object[]] $Selected = @(),
        [string] $ComputerName = $env:COMPUTERNAME
    )
    $base = if (@($Selected).Count -gt 0) { @($Selected) } else { @($Result) }
    $findings = [System.Collections.Generic.List[object]]::new()
    $remote = 0; $notOpen = 0
    foreach ($r in $base) {
        $hostName = [string](Get-WoscapObjectProperty $r 'Host' '')
        if (-not [string]::Equals($hostName, $ComputerName, [System.StringComparison]::OrdinalIgnoreCase)) { $remote++; continue }
        if ([string](Get-WoscapObjectProperty $r 'Status' '') -ne 'Open') { $notOpen++; continue }
        $findings.Add($r)
    }
    [pscustomobject]@{ Findings = $findings.ToArray(); SkippedRemote = $remote; SkippedNotOpen = $notOpen }
}

function Test-WoscapGuiElevated {
    <# True when this process runs as Administrator; registry/audit writes need it. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $principal = [System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()
    [bool]$principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-WoscapGuiSelectedResult {
    <# The result objects behind the grid's selected rows (row.Tag, set by Update-WoscapGuiGrid). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Windows.Forms.DataGridView] $Grid)
    @($Grid.SelectedRows | ForEach-Object { $_.Tag } | Where-Object { $null -ne $_ })
}

function Get-WoscapGuiVisibleResult {
    <# The result objects behind every row the grid currently shows (after the filters). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Windows.Forms.DataGridView] $Grid)
    @($Grid.Rows | ForEach-Object { $_.Tag } | Where-Object { $null -ne $_ })
}

function Test-WoscapGuiSelectionKey {
    <# True for keys with which an operator changes the grid selection on purpose. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][System.Windows.Forms.KeyEventArgs] $KeyEvent)
    $nav = 'Up', 'Down', 'PageUp', 'PageDown', 'Home', 'End'
    [bool](([string]$KeyEvent.KeyCode -in $nav) -or ($KeyEvent.Control -and $KeyEvent.KeyCode -eq 'A'))
}

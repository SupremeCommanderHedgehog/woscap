function Update-WoscapGuiGrid {
    <#
        The single point that mutates the results DataGridView: clears existing rows
        and adds one row per result (manual population — DataGridView does not
        auto-bind pscustomobject properties). Columns must already exist on the grid.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Windows.Forms.DataGridView] $Grid,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rows
    )
    # Batch the rebuild: with AutoSizeColumnsMode='Fill', every Rows.Add and every
    # cell-style write would otherwise trigger a full column recompute + repaint.
    # Suspending layout collapses that to a single pass when we resume.
    $Grid.SuspendLayout()
    try {
        $Grid.Rows.Clear()
        # There are only four distinct status styles; resolve each once and reuse it
        # rather than recomputing (Add-Type + Color.FromArgb) per row.
        $styleCache = @{}
        foreach ($r in $Rows) {
            $exc = if ($r.Exception -and $r.Exception.PSObject.Properties['Type']) { [string]$r.Exception.Type } else { '' }
            $idx = $Grid.Rows.Add($r.Host, $r.StigId, $r.Severity, $r.Status, $r.Title, $exc)
            # Color the whole row by status so Open findings stand out. Unknown/blank
            # statuses return $null -> row keeps the grid's default colors.
            $status = [string]$r.Status
            if (-not $styleCache.ContainsKey($status)) {
                $styleCache[$status] = Get-WoscapGuiStatusStyle -Status $status
            }
            $style = $styleCache[$status]
            if ($style) {
                $Grid.Rows[$idx].DefaultCellStyle.BackColor = $style.BackColor
                $Grid.Rows[$idx].DefaultCellStyle.ForeColor = $style.ForeColor
            }
        }
    } finally {
        $Grid.ResumeLayout()
    }
}

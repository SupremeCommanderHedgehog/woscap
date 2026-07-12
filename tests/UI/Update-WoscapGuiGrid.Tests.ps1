BeforeDiscovery {
    # DataGridView construction needs an STA apartment; SKIP (never fail) on MTA hosts.
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Update-WoscapGuiGrid' -Skip:(-not $script:IsSta) {

    It 'paints each row background by status and leaves unknown statuses default' {
        InModuleScope woscap {
            $grid = New-Object System.Windows.Forms.DataGridView
            $grid.AllowUserToAddRows = $false   # match the real grid (no phantom new-row)
            try {
                foreach ($col in 'Host','StigId','Severity','Status','Title','Exception') {
                    [void]$grid.Columns.Add($col, $col)
                }
                $rows = @(
                    [pscustomobject]@{ Host='H'; StigId='V-1'; Severity='high';   Status='Open';        Title='t'; Exception=$null }
                    [pscustomobject]@{ Host='H'; StigId='V-2'; Severity='medium'; Status='NotAFinding'; Title='t'; Exception=$null }
                    [pscustomobject]@{ Host='H'; StigId='V-3'; Severity='low';    Status='Weird';       Title='t'; Exception=$null }
                )
                Update-WoscapGuiGrid -Grid $grid -Rows $rows

                $grid.Rows.Count | Should -Be 3
                $open = Get-WoscapGuiStatusStyle -Status 'Open'
                $grid.Rows[0].DefaultCellStyle.BackColor | Should -Be $open.BackColor
                $grid.Rows[0].DefaultCellStyle.ForeColor | Should -Be $open.ForeColor
                $naf = Get-WoscapGuiStatusStyle -Status 'NotAFinding'
                $grid.Rows[1].DefaultCellStyle.BackColor | Should -Be $naf.BackColor
                # Unknown status -> untouched (DataGridView's empty default color).
                $grid.Rows[2].DefaultCellStyle.BackColor | Should -Be ([System.Drawing.Color]::Empty)
            } finally { $grid.Dispose() }
        }
    }
}

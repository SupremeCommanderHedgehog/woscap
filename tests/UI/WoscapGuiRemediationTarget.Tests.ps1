BeforeDiscovery {
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Select-WoscapGuiRemediationTarget' {
    BeforeAll {
        $script:rows = @(
            [pscustomobject]@{ Host = 'PC1'; StigId = 'V-1'; Status = 'Open' }
            [pscustomobject]@{ Host = 'pc1'; StigId = 'V-2'; Status = 'Open' }
            [pscustomobject]@{ Host = 'PC1'; StigId = 'V-3'; Status = 'NotAFinding' }
            [pscustomobject]@{ Host = 'SRV9'; StigId = 'V-4'; Status = 'Open' }
        )
    }
    It 'uses all results when nothing is selected, keeping local Open rows only' {
        InModuleScope woscap -Parameters @{ Rows = $script:rows } {
            param($Rows)
            $t = Select-WoscapGuiRemediationTarget -Result $Rows -Selected @() -ComputerName 'PC1'
            @($t.Findings | ForEach-Object StigId) | Should -Be @('V-1', 'V-2')
            $t.SkippedRemote  | Should -Be 1
            $t.SkippedNotOpen | Should -Be 1
        }
    }
    It 'uses only the selection when one exists' {
        InModuleScope woscap -Parameters @{ Rows = $script:rows } {
            param($Rows)
            $t = Select-WoscapGuiRemediationTarget -Result $Rows -Selected @($Rows[1], $Rows[3]) -ComputerName 'PC1'
            @($t.Findings | ForEach-Object StigId) | Should -Be @('V-2')
            $t.SkippedRemote  | Should -Be 1
            $t.SkippedNotOpen | Should -Be 0
        }
    }
    It 'returns no findings (not an error) when nothing qualifies' {
        InModuleScope woscap -Parameters @{ Rows = $script:rows } {
            param($Rows)
            $t = Select-WoscapGuiRemediationTarget -Result @($Rows[3]) -Selected @() -ComputerName 'PC1'
            @($t.Findings).Count | Should -Be 0
        }
    }
    It 'tolerates rows missing Host/Status under strict mode' {
        InModuleScope woscap {
            $t = Select-WoscapGuiRemediationTarget -Result @([pscustomobject]@{ StigId = 'V-9' }) -Selected @() -ComputerName 'PC1'
            @($t.Findings).Count | Should -Be 0
            $t.SkippedRemote | Should -Be 1
        }
    }
}

Describe 'Test-WoscapGuiElevated' {
    It 'returns a bool' {
        InModuleScope woscap { Test-WoscapGuiElevated | Should -BeOfType [bool] }
    }
}

Describe 'Get-WoscapGuiSelectedResult' -Skip:(-not $script:IsSta) {
    It 'returns the result objects behind the selected grid rows' {
        InModuleScope woscap {
            $form = New-Object System.Windows.Forms.Form
            $grid = New-Object System.Windows.Forms.DataGridView
            $grid.Dock = 'Fill'; $grid.AllowUserToAddRows = $false; $grid.SelectionMode = 'FullRowSelect'
            [void]$grid.Columns.Add('StigId', 'StigId')
            $form.Controls.Add($grid)
            try {
                $a = [pscustomobject]@{ StigId = 'V-1' }; $b = [pscustomobject]@{ StigId = 'V-2' }
                foreach ($r in $a, $b) { $i = $grid.Rows.Add($r.StigId); $grid.Rows[$i].Tag = $r }
                $form.Show(); [System.Windows.Forms.Application]::DoEvents()
                $grid.ClearSelection(); $grid.Rows[1].Selected = $true
                $sel = @(Get-WoscapGuiSelectedResult -Grid $grid)
                $sel.Count | Should -Be 1
                [object]::ReferenceEquals($sel[0], $b) | Should -BeTrue
            } finally { $form.Close(); $form.Dispose() }
        }
    }
}

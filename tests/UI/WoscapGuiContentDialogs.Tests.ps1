BeforeDiscovery {
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms
    $script:LongName = 'Microsoft_Windows_Server_2022_Very_Long_Benchmark_Name_That_Has_No_Spaces_At_All_' + ('X' * 60)
    $script:LongUrl = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/' + ('segment/' * 30) + 'U_Long_STIG.zip'
    $script:LongNotice = ('This is a long DISA notice paragraph that should wrap and scroll inside the dialog. ' * 40)
    $script:LongRoot = 'C:\ProgramData\woscap\content\' + ('deeply\nested\' * 15) + 'cache'
    $script:WhatIfRows = @(
        [pscustomobject]@{ Benchmark = 'Edge';      Status = 'WhatIf'; FromRevision = 'V2R1'; ToRevision = ''; Reason = 'Would refresh from DISA' }
        [pscustomobject]@{ Benchmark = 'Windows11'; Status = 'WhatIf'; FromRevision = 'V1R6'; ToRevision = ''; Reason = 'Would refresh from DISA' }
    )

    # Every visible control must sit inside its parent's client area; buttons must also be inside the form vertically.
    function Assert-InsideParent([System.Windows.Forms.Control] $Root) {
        foreach ($c in $Root.Controls) {
            if ($c.Visible) {
                $c.Left  | Should -BeGreaterOrEqual 0 -Because "$($c.GetType().Name) '$($c.Text)'"
                $c.Right | Should -BeLessOrEqual $c.Parent.ClientSize.Width -Because "$($c.GetType().Name) '$($c.Text)' R=$($c.Right) W=$($c.Parent.ClientSize.Width)"
                if ($c -is [System.Windows.Forms.Button]) {
                    $f = $c.FindForm()
                    $r = $f.RectangleToClient($c.RectangleToScreen($c.ClientRectangle))
                    $r.Bottom | Should -BeLessOrEqual $f.ClientSize.Height -Because "button '$($c.Text)' B=$($r.Bottom) H=$($f.ClientSize.Height)"
                    $r.Right  | Should -BeLessOrEqual $f.ClientSize.Width -Because "button '$($c.Text)'"
                }
            }
            Assert-InsideParent $c
        }
    }
    function Test-Shown([System.Windows.Forms.Form] $Form, [switch] $Minimum) {
        try {
            $Form.Show()
            if ($Minimum) { $Form.Size = $Form.MinimumSize }
            [System.Windows.Forms.Application]::DoEvents()
            Assert-InsideParent $Form
        } finally { $Form.Close(); $Form.Dispose() }
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Download dialog' -Skip:(-not $script:IsSta) {
    It 'offers the manifest benchmarks in an editable list' {
        InModuleScope woscap {
            $d = New-WoscapGuiDownloadDialog
            try {
                $combo = $d.Tag['Benchmark']
                $combo.DropDownStyle | Should -Be ([System.Windows.Forms.ComboBoxStyle]::DropDown)
                $expected = @((Get-WoscapStigManifest).Keys | Sort-Object)
                @($combo.Items) | Should -Be $expected
                $d.Tag['AllowScrape'].Checked | Should -BeFalse
                $d.Tag['Force'].Checked | Should -BeFalse
            } finally { $d.Dispose() }
        }
    }
    It 'returns trimmed fields' {
        InModuleScope woscap {
            Mock Show-WoscapGuiMessage { }
            $d = New-WoscapGuiDownloadDialog
            try {
                $d.Tag['Benchmark'].Text = '  Edge  '
                $d.Tag['Url'].Text = '  https://example.test/x.zip '
                $d.Tag['AllowScrape'].Checked = $true
                $d.Tag['Force'].Checked = $true
                Confirm-WoscapGuiDownloadDialog -Form $d | Should -BeTrue
                $d.DialogResult | Should -Be ([System.Windows.Forms.DialogResult]::OK)
                $r = Get-WoscapGuiDownloadRequest -Tag $d.Tag
                $r.Benchmark   | Should -BeExactly 'Edge'
                $r.Url         | Should -BeExactly 'https://example.test/x.zip'
                $r.AllowScrape | Should -BeTrue
                $r.Force       | Should -BeTrue
                @($r.Keys | Sort-Object) | Should -Be @('AllowScrape', 'Benchmark', 'Force', 'Url')
                Should -Invoke Show-WoscapGuiMessage -Times 0 -Exactly
            } finally { $d.Dispose() }
        }
    }
    It 'returns an empty Url and false switches when left blank' {
        InModuleScope woscap {
            Mock Show-WoscapGuiMessage { }
            $d = New-WoscapGuiDownloadDialog
            try {
                $d.Tag['Benchmark'].Text = 'Edge'
                $d.Tag['Url'].Text = '   '
                $r = Get-WoscapGuiDownloadRequest -Tag $d.Tag
                $r.Url | Should -BeExactly ''
                $r.AllowScrape | Should -BeFalse
                $r.Force | Should -BeFalse
            } finally { $d.Dispose() }
        }
    }
    It 'shows a message and stays open for an unsafe or blank benchmark name (<Name>)' -ForEach @(
        @{ Name = '..\evil' }, @{ Name = '..' }, @{ Name = 'a/b' }, @{ Name = 'bad name' }, @{ Name = '   ' }
    ) {
        InModuleScope woscap -Parameters @{ Name = $Name } {
            param($Name)
            Mock Show-WoscapGuiMessage { }
            $d = New-WoscapGuiDownloadDialog
            try {
                $d.Tag['Benchmark'].Text = $Name
                { Confirm-WoscapGuiDownloadDialog -Form $d } | Should -Not -Throw
                Confirm-WoscapGuiDownloadDialog -Form $d | Should -BeFalse
                $d.DialogResult | Should -Not -Be ([System.Windows.Forms.DialogResult]::OK)
                Should -Invoke Show-WoscapGuiMessage -Times 1
            } finally { $d.Dispose() }
        }
    }
    It 'validates when Download is clicked (shown form)' {
        InModuleScope woscap {
            Mock Show-WoscapGuiMessage { }
            $d = New-WoscapGuiDownloadDialog
            try {
                $d.Show(); [System.Windows.Forms.Application]::DoEvents()
                $d.Tag['Benchmark'].Text = '..'
                $d.Tag['Download'].PerformClick()
                Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly
                $d.DialogResult | Should -Not -Be ([System.Windows.Forms.DialogResult]::OK)
            } finally { $d.Close(); $d.Dispose() }
        }
    }
    It 'never makes Download the accept button; Cancel is the cancel button' {
        InModuleScope woscap {
            $d = New-WoscapGuiDownloadDialog
            try {
                $d.AcceptButton | Should -BeNullOrEmpty
                $d.CancelButton | Should -Be $d.Tag['Cancel']
                $d.Tag['Download'].DialogResult | Should -Be ([System.Windows.Forms.DialogResult]::None)
            } finally { $d.Dispose() }
        }
    }
    It 'keeps every control inside its parent when shown (<Case>, minimum=<Min>)' -ForEach @(
        @{ Case = 'empty'; Min = $false; Long = $false }
        @{ Case = 'empty'; Min = $true;  Long = $false }
        @{ Case = 'long name and URL'; Min = $false; Long = $true }
        @{ Case = 'long name and URL'; Min = $true;  Long = $true }
    ) {
        $d = InModuleScope woscap { New-WoscapGuiDownloadDialog }
        if ($Long) { $d.Tag['Benchmark'].Text = $script:LongName; $d.Tag['Url'].Text = $script:LongUrl }
        Test-Shown $d -Minimum:$Min
    }
}

Describe 'Update options dialog' -Skip:(-not $script:IsSta) {
    It 'enables URL only for a single benchmark' -ForEach @(
        @{ Benchmark = 'Edge'; Enabled = $true }
        @{ Benchmark = '';     Enabled = $false }
    ) {
        InModuleScope woscap -Parameters @{ Benchmark = $Benchmark; Enabled = $Enabled } {
            param($Benchmark, $Enabled)
            $d = New-WoscapGuiUpdateDialog -Benchmark $Benchmark
            try {
                $d.Tag['Url'].Enabled | Should -Be $Enabled
                $d.Tag['AllowScrape'].Checked | Should -BeFalse
            } finally { $d.Dispose() }
        }
    }
    It 'names the scope in the header' {
        InModuleScope woscap {
            $one = New-WoscapGuiUpdateDialog -Benchmark 'Edge'
            $all = New-WoscapGuiUpdateDialog -Benchmark ''
            try {
                $one.Tag['Header'].Text | Should -Match 'Edge'
                $all.Tag['Header'].Text | Should -Match 'every cached benchmark'
            } finally { $one.Dispose(); $all.Dispose() }
        }
    }
    It 'returns trimmed options; Url is empty when updating every benchmark' {
        InModuleScope woscap {
            $one = New-WoscapGuiUpdateDialog -Benchmark 'Edge'
            $all = New-WoscapGuiUpdateDialog -Benchmark ''
            try {
                $one.Tag['Url'].Text = ' https://example.test/e.zip  '
                $one.Tag['AllowScrape'].Checked = $true
                $r = Get-WoscapGuiUpdateOptions -Tag $one.Tag
                $r.Url | Should -BeExactly 'https://example.test/e.zip'
                $r.AllowScrape | Should -BeTrue
                $all.Tag['Url'].Text = 'https://example.test/ignored.zip'
                (Get-WoscapGuiUpdateOptions -Tag $all.Tag).Url | Should -BeExactly ''
            } finally { $one.Dispose(); $all.Dispose() }
        }
    }
    It 'has no accept button; Cancel is the cancel button' {
        InModuleScope woscap {
            $d = New-WoscapGuiUpdateDialog -Benchmark 'Edge'
            try {
                $d.AcceptButton | Should -BeNullOrEmpty
                $d.CancelButton | Should -Be $d.Tag['Cancel']
            } finally { $d.Dispose() }
        }
    }
    It 'keeps every control inside its parent when shown (<Case>, minimum=<Min>)' -ForEach @(
        @{ Case = 'single'; Min = $false; Long = $false }
        @{ Case = 'single'; Min = $true;  Long = $false }
        @{ Case = 'long';   Min = $false; Long = $true }
        @{ Case = 'long';   Min = $true;  Long = $true }
    ) {
        $name = if ($Long) { $script:LongName } else { 'Edge' }
        $d = InModuleScope woscap -Parameters @{ N = $name } { param($N) New-WoscapGuiUpdateDialog -Benchmark $N }
        if ($Long) { $d.Tag['Url'].Text = $script:LongUrl }
        Test-Shown $d -Minimum:$Min
    }
}

Describe 'Update confirmation dialog' -Skip:(-not $script:IsSta) {
    It 'lists exactly the WhatIf rows' {
        InModuleScope woscap -Parameters @{ Rows = $script:WhatIfRows } {
            param($Rows)
            $d = New-WoscapGuiUpdateConfirmDialog -Rows $Rows
            try {
                $g = $d.Tag['Grid']
                $g.Rows.Count | Should -Be 2
                $g.Rows[0].Cells[0].Value | Should -Be 'Edge'
                $g.Rows[0].Cells[1].Value | Should -Be 'V2R1'
                $g.Rows[1].Cells[0].Value | Should -Be 'Windows11'
                $g.Rows[1].Tag | Should -Be $Rows[1]
                $d.Tag['Header'].Text | Should -Match '2 benchmarks'
            } finally { $d.Dispose() }
        }
    }
    It 'never makes Update the accept button; Cancel is the cancel button' {
        InModuleScope woscap -Parameters @{ Rows = $script:WhatIfRows } {
            param($Rows)
            $d = New-WoscapGuiUpdateConfirmDialog -Rows $Rows
            try {
                $d.AcceptButton | Should -BeNullOrEmpty
                $d.CancelButton | Should -Be $d.Tag['Cancel']
                $d.Tag['Update'].DialogResult | Should -Be ([System.Windows.Forms.DialogResult]::OK)
            } finally { $d.Dispose() }
        }
    }
    It 'keeps every control inside its parent when shown (minimum=<Min>)' -ForEach @(@{ Min = $false }, @{ Min = $true }) {
        $rows = @($script:WhatIfRows) + [pscustomobject]@{ Benchmark = $script:LongName; Status = 'WhatIf'; FromRevision = 'V1R1'; ToRevision = ''; Reason = 'Would refresh from DISA' }
        $d = InModuleScope woscap -Parameters @{ Rows = $rows } { param($Rows) New-WoscapGuiUpdateConfirmDialog -Rows $Rows }
        Test-Shown $d -Minimum:$Min
    }
}

Describe 'Update report' -Skip:(-not $script:IsSta) {
    It 'shows Benchmark/Status/From/To/Reason per row with counts' {
        InModuleScope woscap {
            $res = @(
                [pscustomobject]@{ Benchmark = 'Edge'; Status = 'Updated'; FromRevision = 'V2R1'; ToRevision = 'V2R2'; Reason = '' }
                [pscustomobject]@{ Benchmark = 'Chrome'; Status = 'AlreadyCurrent'; FromRevision = 'V2R9'; ToRevision = 'V2R9'; Reason = '' }
                [pscustomobject]@{ Benchmark = 'Windows11'; Status = 'Failed'; FromRevision = 'V1R6'; ToRevision = ''; Reason = 'network down' }
            )
            $d = New-WoscapGuiUpdateReport -Result $res
            try {
                $g = $d.Tag['Grid']
                @($g.Columns | ForEach-Object HeaderText) | Should -Be @('Benchmark', 'Status', 'From', 'To', 'Reason')
                $g.Rows.Count | Should -Be 3
                @($g.Rows[2].Cells | ForEach-Object Value) | Should -Be @('Windows11', 'Failed', 'V1R6', '', 'network down')
                $d.Tag['Summary'].Text | Should -Match 'Updated: 1'
                $d.Tag['Summary'].Text | Should -Match 'Already current: 1'
                $d.Tag['Summary'].Text | Should -Match 'Failed: 1'
                $d.CancelButton | Should -Be $d.Tag['Close']
            } finally { $d.Dispose() }
        }
    }
    It 'keeps every control inside its parent when shown (minimum=<Min>)' -ForEach @(@{ Min = $false }, @{ Min = $true }) {
        $d = InModuleScope woscap -Parameters @{ N = $script:LongName } {
            param($N)
            New-WoscapGuiUpdateReport -Result @([pscustomobject]@{ Benchmark = $N; Status = 'Failed'; FromRevision = 'V1R1'; ToRevision = ''; Reason = ('error ' * 50) })
        }
        Test-Shown $d -Minimum:$Min
    }
}

Describe 'Remove dialog' -Skip:(-not $script:IsSta) {
    It 'defaults to this revision only and names benchmark, revision and cache root' {
        InModuleScope woscap {
            $d = New-WoscapGuiRemoveDialog -Benchmark 'Edge' -Revision 'V2R1' -CacheRoot 'C:\cache\root'
            try {
                $d.Tag['ThisRevision'].Checked | Should -BeTrue
                $d.Tag['AllRevisions'].Checked | Should -BeFalse
                $d.Tag['AllRevisions'].Text | Should -Match 'All revisions of Edge'
                $d.Tag['BenchmarkText'].Text | Should -Be 'Edge'
                $d.Tag['RevisionText'].Text | Should -Be 'V2R1'
                $d.Tag['CacheRootText'].Text | Should -Be 'C:\cache\root'
                (Get-WoscapGuiRemoveChoice -Tag $d.Tag).AllRevisions | Should -BeFalse
                $d.Tag['AllRevisions'].Checked = $true
                $choice = Get-WoscapGuiRemoveChoice -Tag $d.Tag
                $choice.AllRevisions | Should -BeTrue
                @($choice.Keys) | Should -Be @('AllRevisions')
            } finally { $d.Dispose() }
        }
    }
    It 'never makes Remove the accept button; Cancel is the cancel button' {
        InModuleScope woscap {
            $d = New-WoscapGuiRemoveDialog -Benchmark 'Edge' -Revision 'V2R1' -CacheRoot 'C:\cache'
            try {
                $d.AcceptButton | Should -BeNullOrEmpty
                $d.CancelButton | Should -Be $d.Tag['Cancel']
                $d.Tag['Remove'].DialogResult | Should -Be ([System.Windows.Forms.DialogResult]::OK)
            } finally { $d.Dispose() }
        }
    }
    It 'keeps every control inside its parent when shown (<Case>, minimum=<Min>)' -ForEach @(
        @{ Case = 'short'; Min = $false; Long = $false }
        @{ Case = 'short'; Min = $true;  Long = $false }
        @{ Case = 'long';  Min = $false; Long = $true }
        @{ Case = 'long';  Min = $true;  Long = $true }
    ) {
        $p = if ($Long) { @{ B = $script:LongName; R = 'V1R1'; C = $script:LongRoot } } else { @{ B = 'Edge'; R = 'V2R1'; C = 'C:\cache' } }
        $d = InModuleScope woscap -Parameters $p { param($B, $R, $C) New-WoscapGuiRemoveDialog -Benchmark $B -Revision $R -CacheRoot $C }
        Test-Shown $d -Minimum:$Min
    }
}

Describe 'DISA terms dialog' -Skip:(-not $script:IsSta) {
    It 'shows the shared DISA notice with Remember unticked' {
        InModuleScope woscap {
            $notice = Get-WoscapDisaNotice
            $d = New-WoscapGuiDisaTermsDialog -Notice $notice
            try {
                $d.Tag['Notice'].Text | Should -Match ([regex]::Escape('does NOT bundle or redistribute DISA STIG content'))
                ($d.Tag['Notice'].Text -replace '\r\n', "`n").Trim() | Should -BeExactly (($notice -replace '\r\n', "`n").Trim())
                $d.Tag['Notice'].ReadOnly | Should -BeTrue
                $d.Tag['Remember'].Checked | Should -BeFalse
                (Get-WoscapGuiDisaTermsChoice -Tag $d.Tag).Remember | Should -BeFalse
                $d.Tag['Remember'].Checked = $true
                (Get-WoscapGuiDisaTermsChoice -Tag $d.Tag).Remember | Should -BeTrue
            } finally { $d.Dispose() }
        }
    }
    It 'never makes Accept the accept button; Cancel is the cancel button' {
        InModuleScope woscap {
            $d = New-WoscapGuiDisaTermsDialog -Notice 'n'
            try {
                $d.AcceptButton | Should -BeNullOrEmpty
                $d.CancelButton | Should -Be $d.Tag['Cancel']
                $d.Tag['Accept'].DialogResult | Should -Be ([System.Windows.Forms.DialogResult]::OK)
            } finally { $d.Dispose() }
        }
    }
    It 'keeps every control inside its parent when shown (<Case>, minimum=<Min>)' -ForEach @(
        @{ Case = 'shared notice'; Min = $false; Long = $false }
        @{ Case = 'shared notice'; Min = $true;  Long = $false }
        @{ Case = 'long notice';   Min = $false; Long = $true }
        @{ Case = 'long notice';   Min = $true;  Long = $true }
    ) {
        $n = if ($Long) { $script:LongNotice } else { $null }
        $d = InModuleScope woscap -Parameters @{ N = $n } {
            param($N)
            if (-not $N) { $N = Get-WoscapDisaNotice }
            New-WoscapGuiDisaTermsDialog -Notice $N
        }
        Test-Shown $d -Minimum:$Min
    }
}

Describe 'Content dialog seams' -Skip:(-not $script:IsSta) {
    It 'Show-WoscapGuiDisaTermsDialog no longer throws the placeholder error' {
        InModuleScope woscap {
            (Get-Command Show-WoscapGuiDisaTermsDialog).Definition | Should -Not -Match 'not available yet'
            (Get-Command Show-WoscapGuiDisaTermsDialog).Definition | Should -Match 'ShowDialog'
        }
    }
    It 'exposes every seam' -ForEach @(
        @{ Name = 'Show-WoscapGuiDownloadDialog' }, @{ Name = 'Show-WoscapGuiUpdateDialog' },
        @{ Name = 'Show-WoscapGuiUpdateConfirmDialog' }, @{ Name = 'Show-WoscapGuiUpdateReport' },
        @{ Name = 'Show-WoscapGuiRemoveDialog' }, @{ Name = 'Show-WoscapGuiDisaTermsDialog' }
    ) {
        InModuleScope woscap -Parameters @{ Name = $Name } {
            param($Name)
            Get-Command $Name -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
}

BeforeDiscovery {
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms

    # A cache laid out the way Get-WoscapBenchmark reads it: <root>\<bench>\<rev>\*_Manual-xccdf.xml + sidecar.
    function New-TestCache([string] $Root) {
        $revs = @(
            @{ Bench = 'Windows11'; Rev = 'V1R5'; Hash = ('A' * 64); Title = 'Windows 11 STIG' }
            @{ Bench = 'Windows11'; Rev = 'V1R6'; Hash = ('B' * 64); Title = 'Windows 11 STIG' }
            @{ Bench = 'Edge';      Rev = 'V2R1'; Hash = ('C' * 64); Title = 'Edge STIG' }
        )
        foreach ($r in $revs) { Add-TestRevision -Root $Root @r }
        $Root
    }
    function Add-TestRevision([string] $Root, [string] $Bench, [string] $Rev, [string] $Hash, [string] $Title) {
        $rd = Join-Path (Join-Path $Root $Bench) $Rev
        New-Item -ItemType Directory -Path $rd -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $rd ("U_{0}_Manual-xccdf.xml" -f $Bench)) -Value '<Benchmark/>'
        $sidecar = InModuleScope woscap -Parameters @{ Rd = $rd } { param($Rd) Get-WoscapContentSidecarPath -RevisionDir $Rd }
        Set-Content -LiteralPath $sidecar -Value (@{
            benchmark = $Bench; revision = $Rev; contentSha256 = $Hash; title = $Title
            sourceUrl = "https://example.invalid/$Bench.zip"
        } | ConvertTo-Json)
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Content tab' -Skip:(-not $script:IsSta) {
    BeforeEach {
        # Never pop a real modal, and never list the real cache: a blank Destination fails loudly.
        Mock -ModuleName woscap Show-WoscapGuiMessage { }
        Mock -ModuleName woscap Show-WoscapGuiDownloadDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiUpdateDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiUpdateConfirmDialog { $false }
        Mock -ModuleName woscap Show-WoscapGuiUpdateReport { }
        Mock -ModuleName woscap Show-WoscapGuiRemoveDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiDisaTermsDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiRemediationDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiRemediationReport { }
        Mock -ModuleName woscap Get-WoscapGuiFolderPath { $null }
        # Pester 6 has no fall-through for unmatched filters, so the guard delegates to the real
        # reader (the mock is an alias; function: still holds the original).
        Mock -ModuleName woscap Get-WoscapBenchmark {
            if ([string]::IsNullOrWhiteSpace($Destination)) { throw 'test tried to list the real content cache' }
            $splat = @{ Destination = $Destination }
            if ($Benchmark) { $splat['Benchmark'] = $Benchmark }
            & (Get-Item -LiteralPath function:Get-WoscapBenchmark) @splat
        }
        InModuleScope woscap {
            # Button.PerformClick is a no-op unless the button is visible; raise Click directly.
            function script:Invoke-WoscapTestClick([System.Windows.Forms.Button] $Button) {
                $m = [System.Windows.Forms.Button].GetMethod('OnClick', [System.Reflection.BindingFlags]'Instance, NonPublic')
                [void]$m.Invoke($Button, @([System.EventArgs]::Empty))
            }
        }
        $script:Cache = New-TestCache (Join-Path $TestDrive ('cache-' + [guid]::NewGuid().ToString('N')))
    }

    It 'exposes every Content Tag key' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                foreach ($key in 'ContentDestination','ContentDestinationDefault','ContentDestinationBrowse','ContentFilter',
                                 'ContentGrid','ContentDownload','ContentUpdate','ContentRemove','ContentUseForScan',
                                 'ContentRefresh','ContentStatus','MenuContentDownload','MenuContentUpdate',
                                 'MenuContentRemove','MenuContentUseForScan','MenuContentRefresh') {
                    $form.Tag.ContainsKey($key) | Should -BeTrue -Because "Tag should expose '$key'"
                    $form.Tag[$key] | Should -Not -BeNullOrEmpty -Because "'$key' must be a control"
                }
            } finally { $form.Dispose() }
        }
    }

    It 'replaces the #17 placeholder with real controls on the Content tab' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $walk = { param($c) foreach ($child in $c.Controls) { $child; & $walk $child } }
                @(& $walk $form.Tag['ContentTab'] | Where-Object { $_.Text -match 'coming in #17' }) | Should -BeNullOrEmpty
                $form.Tag['ContentGrid'].FindForm() | Should -Be $form
                $form.Tag['ContentGrid'].Columns.Count | Should -Be 5
            } finally { $form.Dispose() }
        }
    }

    It 'has Content menu items Download, Update, Remove, Use for scan, Refresh and Open Content tab' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $content = @($form.Tag['Menu'].Items | Where-Object { $_.Text -eq '&Content' })[0]
                $texts = @($content.DropDownItems | Where-Object { $_ -is [System.Windows.Forms.ToolStripMenuItem] } | ForEach-Object Text)
                $texts | Should -Be @('&Download...', '&Update...', '&Remove...', 'Use for &scan', 'Re&fresh', 'Open &Content tab')
                foreach ($k in 'MenuContentDownload','MenuContentUpdate','MenuContentRemove','MenuContentUseForScan','MenuContentRefresh') {
                    $content.DropDownItems.Contains($form.Tag[$k]) | Should -BeTrue -Because "$k must live under the Content menu"
                }
            } finally { $form.Dispose() }
        }
    }

    It 'never makes a content button the form AcceptButton' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                foreach ($k in 'ContentDownload','ContentUpdate','ContentRemove','ContentUseForScan') {
                    $form.AcceptButton | Should -Not -Be $form.Tag[$k]
                }
            } finally { $form.Dispose() }
        }
    }

    It 'shows the resolved default cache root in the grey label' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $form.Tag['ContentDestinationDefault'].Text | Should -BeLike ('*' + (Get-WoscapContentCacheRoot) + '*')
                $form.Tag['ContentDestinationDefault'].ForeColor | Should -Be ([System.Drawing.SystemColors]::GrayText)
            } finally { $form.Dispose() }
        }
    }

    It 'starts with Remove and Use for scan disabled on button and menu, and lists nothing before the tab is shown' {
        InModuleScope woscap {
            Mock Get-WoscapBenchmark { throw 'must not list at build time' }
            $form = New-WoscapMainForm
            try {
                foreach ($k in 'ContentRemove','MenuContentRemove','ContentUseForScan','MenuContentUseForScan') {
                    $form.Tag[$k].Enabled | Should -BeFalse -Because "$k needs a selected row"
                }
                $form.Tag['ContentGrid'].Rows.Count | Should -Be 0
                Should -Invoke Get-WoscapBenchmark -Times 0 -Exactly
            } finally { $form.Dispose() }
        }
    }

    It 'lists the cache on first selection of the tab and fills the grid and filter (real Get-WoscapBenchmark)' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['ContentDestination'].Text = "  $Cache  "
                $form.Show(); [System.Windows.Forms.Application]::DoEvents()
                $t['Tabs'].SelectedTab = $t['ContentTab']
                [System.Windows.Forms.Application]::DoEvents()

                $grid = $t['ContentGrid']
                $grid.Rows.Count | Should -Be 3
                $rows = @($grid.Rows | ForEach-Object { $_.Tag })
                @($rows | ForEach-Object { '{0}/{1}' -f $_.Benchmark, $_.Revision } | Sort-Object) |
                    Should -Be @('Edge/V2R1', 'Windows11/V1R5', 'Windows11/V1R6')
                foreach ($r in $rows) { $r.Path | Should -BeLike "$Cache*" }
                $edge = @($grid.Rows | Where-Object { $_.Tag.Benchmark -eq 'Edge' })[0]
                $edge.Cells[3].Value | Should -Be ('C' * 12)
                $edge.Cells[4].Value | Should -Be 'https://example.invalid/Edge.zip'
                @($t['ContentFilter'].Items) | Should -Be @('All', 'Edge', 'Windows11')
                $t['ContentFilter'].SelectedItem | Should -Be 'All'
                $t['ContentStatus'].Text | Should -Match '3'
            } finally { $form.Close(); $form.Dispose() }
        }
    }

    It 'narrows the grid with the benchmark filter and keeps the full filter list' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['ContentDestination'].Text = $Cache
                Update-WoscapGuiContentView -Tag $t
                $t['ContentFilter'].SelectedItem = 'Windows11'
                [System.Windows.Forms.Application]::DoEvents()
                @($t['ContentGrid'].Rows | ForEach-Object { $_.Tag.Benchmark } | Select-Object -Unique) | Should -Be @('Windows11')
                $t['ContentGrid'].Rows.Count | Should -Be 2
                @($t['ContentFilter'].Items) | Should -Be @('All', 'Edge', 'Windows11')
                $t['ContentFilter'].SelectedItem = 'All'
                $t['ContentGrid'].Rows.Count | Should -Be 3
            } finally { $form.Dispose() }
        }
    }

    It 'passes the filter as -Benchmark and the trimmed Cache folder as -Destination' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            Mock Get-WoscapBenchmark -ParameterFilter { $Destination } {
                $all = @([pscustomobject]@{ Benchmark = 'Edge'; Revision = '1'; Title = ''; SourceUrl = ''; ContentHash = ''; Path = 'x' }
                         [pscustomobject]@{ Benchmark = 'Chrome'; Revision = '1'; Title = ''; SourceUrl = ''; ContentHash = ''; Path = 'y' })
                if ($Benchmark) { $all | Where-Object Benchmark -eq $Benchmark } else { $all }
            }
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['ContentDestination'].Text = "  $Cache "
                Update-WoscapGuiContentView -Tag $t
                $t['ContentFilter'].SelectedItem = 'Edge'
                Should -Invoke Get-WoscapBenchmark -ParameterFilter { $Benchmark -eq 'Edge' -and $Destination -eq $Cache }
                $t['ContentGrid'].Rows.Count | Should -Be 1
            } finally { $form.Dispose() }
        }
    }

    It 'resets the filter to All when the filtered benchmark is no longer cached' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['ContentDestination'].Text = $Cache
                Update-WoscapGuiContentView -Tag $t
                $t['ContentFilter'].SelectedItem = 'Edge'
                Microsoft.PowerShell.Management\Remove-Item -LiteralPath (Join-Path $Cache 'Edge') -Recurse -Force
                Update-WoscapGuiContentView -Tag $t
                $t['ContentFilter'].SelectedItem | Should -Be 'All'
                @($t['ContentFilter'].Items) | Should -Be @('All', 'Windows11')
                $t['ContentGrid'].Rows.Count | Should -Be 2
            } finally { $form.Dispose() }
        }
    }

    It 'Refresh button and Refresh menu re-list the cache' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['ContentDestination'].Text = $Cache
                Invoke-WoscapTestClick $t['ContentRefresh']
                $t['ContentGrid'].Rows.Count | Should -Be 3
                $rd = Join-Path (Join-Path $Cache 'Chrome') 'V2R9'
                New-Item -ItemType Directory -Path $rd -Force | Out-Null
                Set-Content -LiteralPath (Join-Path $rd 'U_Chrome_Manual-xccdf.xml') -Value '<Benchmark/>'
                $t['MenuContentRefresh'].PerformClick()
                $t['ContentGrid'].Rows.Count | Should -Be 4
                @($t['ContentFilter'].Items) | Should -Contain 'Chrome'
            } finally { $form.Close(); $form.Dispose() }
        }
    }

    It 'lists only on the first selection of the tab; later selections do not re-list' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            Mock Get-WoscapBenchmark -ParameterFilter { $Destination } { }
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['ContentDestination'].Text = $Cache
                $form.Show(); [System.Windows.Forms.Application]::DoEvents()
                $t['Tabs'].SelectedTab = $t['ContentTab']
                $t['Tabs'].SelectedTab = $t['ScanTab']
                $t['Tabs'].SelectedTab = $t['ContentTab']
                Should -Invoke Get-WoscapBenchmark -Times 1 -Exactly -ParameterFilter { $Destination }
            } finally { $form.Close(); $form.Dispose() }
        }
    }

    It 'reports a refresh error in the status line and never throws' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['ContentDestination'].Text = $Cache
                Update-WoscapGuiContentView -Tag $t
                $t['ContentGrid'].Rows.Count | Should -Be 3
                Mock Get-WoscapBenchmark -ParameterFilter { $Destination } { throw 'folder is unreadable' }
                { Update-WoscapGuiContentView -Tag $t } | Should -Not -Throw
                $t['ContentStatus'].Text | Should -Match 'folder is unreadable'
                $t['ContentGrid'].Rows.Count | Should -Be 0 -Because 'a failed refresh must not leave stale rows'
                Should -Invoke Show-WoscapGuiMessage -Times 0 -Exactly
            } finally { $form.Dispose() }
        }
    }

    It 'enables Remove and Use for scan (button and menu) only while a row is selected' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['ContentDestination'].Text = $Cache
                $form.Show(); [System.Windows.Forms.Application]::DoEvents()
                $t['Tabs'].SelectedTab = $t['ContentTab']
                [System.Windows.Forms.Application]::DoEvents()
                $grid = $t['ContentGrid']
                $grid.Rows.Count | Should -Be 3
                $keys = 'ContentRemove','MenuContentRemove','ContentUseForScan','MenuContentUseForScan'
                foreach ($k in $keys) { $t[$k].Enabled | Should -BeFalse -Because "$k with no deliberate selection" }

                $grid.Rows[1].Selected = $true
                [System.Windows.Forms.Application]::DoEvents()
                foreach ($k in $keys) { $t[$k].Enabled | Should -BeTrue -Because "$k with a selected row" }

                $grid.ClearSelection()
                [System.Windows.Forms.Application]::DoEvents()
                foreach ($k in $keys) { $t[$k].Enabled | Should -BeFalse -Because "$k after clearing the selection" }

                $grid.Rows[0].Selected = $true
                Update-WoscapGuiContentView -Tag $t
                foreach ($k in $keys) { $t[$k].Enabled | Should -BeFalse -Because "$k after a refresh rebinds the grid" }
            } finally { $form.Close(); $form.Dispose() }
        }
    }

    It 'Browse sets the Cache folder from the folder seam and re-lists' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            Mock Get-WoscapGuiFolderPath { $Cache }.GetNewClosure()
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                Invoke-WoscapTestClick $t['ContentDestinationBrowse']
                Should -Invoke Get-WoscapGuiFolderPath -Times 1 -Exactly
                $t['ContentDestination'].Text | Should -Be $Cache
                $t['ContentGrid'].Rows.Count | Should -Be 3
            } finally { $form.Close(); $form.Dispose() }
        }
    }

    It 'Browse cancelled leaves the Cache folder unchanged and does not list' {
        InModuleScope woscap {
            Mock Get-WoscapGuiFolderPath { $null }
            Mock Get-WoscapBenchmark { throw 'must not list' }
            $form = New-WoscapMainForm
            try {
                $form.Tag['ContentDestination'].Text = 'C:\keep'
                Invoke-WoscapTestClick $form.Tag['ContentDestinationBrowse']
                Should -Invoke Get-WoscapGuiFolderPath -Times 1 -Exactly
                $form.Tag['ContentDestination'].Text | Should -Be 'C:\keep'
                Should -Invoke Get-WoscapBenchmark -Times 0 -Exactly
            } finally { $form.Close(); $form.Dispose() }
        }
    }

    It 'keeps every visible Content-tab control inside its parent at default and minimum size' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['ContentDestination'].Text = $Cache
                $form.Show(); [System.Windows.Forms.Application]::DoEvents()
                $t['Tabs'].SelectedTab = $t['ContentTab']
                [System.Windows.Forms.Application]::DoEvents()
                $t['ContentGrid'].Rows.Count | Should -Be 3
                # Long texts must ellipsize or scroll, never push controls out.
                $t['ContentDestinationDefault'].Text = 'Default: C:\' + ('very\long\path\' * 30)
                $t['ContentStatus'].Text = 'A long status message ' * 20
                $walk = { param($c) foreach ($child in $c.Controls) { $child; & $walk $child } }
                $bad = [System.Collections.Generic.List[string]]::new()
                $checked = 0
                foreach ($size in $form.Size, $form.MinimumSize) {
                    $form.Size = $size
                    [System.Windows.Forms.Application]::DoEvents()
                    foreach ($c in @(& $walk $t['ContentTab'])) {
                        if (-not $c.Visible) { continue }
                        $checked++
                        $w = $c.Parent.ClientSize.Width
                        $h = $c.Parent.ClientSize.Height
                        if ($c.Left -lt 0 -or $c.Right -gt $w -or $c.Top -lt 0 -or $c.Bottom -gt $h) {
                            $bad.Add(('{0} "{1}" L={2} R={3} T={4} B={5} parent={6}x{7} at {8}x{9}' -f
                                $c.GetType().Name, $c.Text, $c.Left, $c.Right, $c.Top, $c.Bottom, $w, $h, $size.Width, $size.Height))
                        }
                    }
                    foreach ($k in 'ContentDownload','ContentUpdate','ContentRemove','ContentUseForScan','ContentRefresh','ContentDestinationBrowse') {
                        $b = $t[$k]
                        $r = $t['ContentTab'].RectangleToClient($b.RectangleToScreen($b.ClientRectangle))
                        if ($r.Right -gt $t['ContentTab'].ClientSize.Width -or $r.Bottom -gt $t['ContentTab'].ClientSize.Height) {
                            $bad.Add(('{0} outside the tab: R={1} B={2} tab={3}x{4}' -f $k, $r.Right, $r.Bottom,
                                $t['ContentTab'].ClientSize.Width, $t['ContentTab'].ClientSize.Height))
                        }
                    }
                }
                $checked | Should -BeGreaterThan 10
                $bad | Should -BeNullOrEmpty -Because 'no Content-tab control may overflow its parent'
            } finally { $form.Close(); $form.Dispose() }
        }
    }
}

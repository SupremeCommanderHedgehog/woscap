BeforeDiscovery {
    # WinForms needs STA; skip (never fail) on an MTA host.
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $script:SpecFields = @('Benchmark', 'XccdfPath', 'Targets', 'Profiles', 'AdvancedExpanded', 'ContentPath',
        'ThrottleLimit', 'JsonPath', 'ExportFormat', 'ContentDestination', 'IntegrationPath', 'Window') | Sort-Object
    $script:SettingsFile = Join-Path $TestDrive 'woscap\gui-settings.json'

    function script:Save-TestSettings([hashtable] $Settings) {
        InModuleScope woscap -Parameters @{ S = $Settings } { param($S) Write-WoscapGuiSettingsFile -Settings $S } | Should -BeTrue
    }
    # Raises FormClosing without showing the form; defined in module scope so InModuleScope blocks see it.
    InModuleScope woscap {
        function script:Invoke-FormClosing($Form) {
            $e = [System.Windows.Forms.FormClosingEventArgs]::new([System.Windows.Forms.CloseReason]::UserClosing, $false)
            $flags = [System.Reflection.BindingFlags]'NonPublic, Instance'
            [void][System.Windows.Forms.Form].GetMethod('OnFormClosing', $flags).Invoke($Form, @($e))
            $e
        }
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'GUI settings applied to the main form' -Skip:(-not $script:IsSta) {
    BeforeAll {
        # Never the real %LOCALAPPDATA%; never a real modal; a fixed 1920x1040 desktop.
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }
        Mock -ModuleName woscap Show-WoscapGuiMessage { }
        Mock -ModuleName woscap Get-WoscapGuiScreenArea { , @(New-Object System.Drawing.Rectangle(0, 0, 1920, 1040)) }

        $script:Dir = Join-Path $TestDrive 'data'
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
        $script:Xccdf = Join-Path $script:Dir 'x.xml'
        $script:ProfA = Join-Path $script:Dir 'a.psd1'
        $script:ProfB = Join-Path $script:Dir 'b.psd1'
        foreach ($f in $script:Xccdf, $script:ProfA, $script:ProfB) { Set-Content -LiteralPath $f -Value 'x' }
    }
    BeforeEach { Remove-Item -LiteralPath $script:SettingsFile -Force -ErrorAction SilentlyContinue }

    It 'round-trips every field through export, a new form and import' {
        $p = @{ Dir = $script:Dir; Xccdf = $script:Xccdf; A = $script:ProfA; B = $script:ProfB }
        InModuleScope woscap -Parameters $p {
            param($Dir, $Xccdf, $A, $B)
            $first = New-WoscapMainForm
            try {
                $t = $first.Tag
                $t['Benchmark'].SelectedItem = 'Edge'
                $t['Xccdf'].Text = $Xccdf
                $t['Targets'].Text = 'host1, host2'
                Add-WoscapGuiProfile -Tag $t -Path @($B, $A)
                Set-WoscapGuiAdvanced -Tag $t -Expanded $true
                $t['ContentPath'].Text = $Dir
                $t['ThrottleLimit'].Value = 9
                $t['JsonPath'].Text = Join-Path $Dir 'out.json'
                $t['Format'].SelectedIndex = $t['Format'].Items.Count - 1
                $t['ContentDestination'].Text = $Dir
                $t['IntegrationPath'].Text = $Dir
                $first.StartPosition = 'Manual'
                $first.Bounds = New-Object System.Drawing.Rectangle(40, 50, 1000, 800)
                $format = [string]$t['Format'].SelectedItem
                Export-WoscapGuiSettings -Tag $t -Form $first
            } finally { $first.Dispose() }

            $second = New-WoscapMainForm
            try {
                $t = $second.Tag
                $t['Benchmark'].SelectedItem | Should -Be 'Edge'
                $t['Xccdf'].Text | Should -Be $Xccdf
                $t['Targets'].Text | Should -Be 'host1, host2'
                @($t['Profiles'].Items) | Should -Be @($B, $A)
                $t['AdvancedExpanded'] | Should -BeTrue
                $t['ContentPath'].Text | Should -Be $Dir
                $t['ThrottleLimit'].Value | Should -Be 9
                $t['JsonPath'].Text | Should -Be (Join-Path $Dir 'out.json')
                $t['Format'].SelectedItem | Should -Be $format
                $t['ContentDestination'].Text | Should -Be $Dir
                $t['IntegrationPath'].Text | Should -Be $Dir
                $second.Bounds | Should -Be (New-Object System.Drawing.Rectangle(40, 50, 1000, 800))
                $second.WindowState | Should -Be 'Normal'
                $t['Status'].Text | Should -BeExactly ''
            } finally { $second.Dispose() }
        }
    }

    It 'exports exactly the spec field set from a form whose credential, results and filters are set' {
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $t = $form.Tag
                $t['UseCred'].Checked = $true
                $t['FilterSeverity'].SelectedIndex = 1
                $t['Find'].Text = 'needle'
                $t['Results'].Add([pscustomobject]@{ StigId = 'V-1' })
                Export-WoscapGuiSettings -Tag $t -Form $form
            } finally { $form.Dispose() }
        }
        $text = Get-Content -LiteralPath $script:SettingsFile -Raw
        $json = $text | ConvertFrom-Json
        @($json.PSObject.Properties.Name | Where-Object { $_ -ne 'Version' } | Sort-Object) | Should -Be $script:SpecFields
        $text | Should -Not -Match 'needle|V-1|UseCred|Credential'
    }

    It 'leaves derived UI in the same state as user edits would' {
        Save-TestSettings @{ Benchmark = 'Edge'; Profiles = @($script:ProfA, $script:ProfB); AdvancedExpanded = $true }
        $p = @{ A = $script:ProfA; B = $script:ProfB }
        InModuleScope woscap -Parameters $p {
            param($A, $B)
            $loaded = New-WoscapMainForm
            Remove-Item -LiteralPath (Get-WoscapGuiSettingsPath) -Force
            $edited = New-WoscapMainForm
            try {
                $e = $edited.Tag
                $e['Benchmark'].SelectedItem = 'Edge'
                Add-WoscapGuiProfile -Tag $e -Path @($A, $B)
                Set-WoscapGuiAdvanced -Tag $e -Expanded $true
                $l = $loaded.Tag
                foreach ($k in 'ProfileRemove', 'ProfileUp', 'ProfileDown') { $l[$k].Enabled | Should -Be $e[$k].Enabled -Because $k }
                $l['AdvancedGroup'].Visible | Should -Be $e['AdvancedGroup'].Visible
                $l['AdvancedToggle'].Text | Should -Be $e['AdvancedToggle'].Text
                $l['AdvancedExpanded'] | Should -BeTrue
                $l['ContentPathDefault'].Text | Should -Be $e['ContentPathDefault'].Text
                $l['ContentPathDefault'].Text | Should -Match 'Edge$'
            } finally { $loaded.Dispose(); $edited.Dispose() }
        }
    }

    It 'reports how many saved paths were cleared on the Scan tab' {
        $gone = Join-Path $TestDrive 'gone'
        Save-TestSettings @{ XccdfPath = (Join-Path $gone 'x.xml'); ContentPath = $gone; Profiles = @($script:ProfA, (Join-Path $gone 'p.psd1')) }
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $form.Tag['Status'].Text | Should -BeExactly '3 saved path(s) no longer exist and were cleared.'
                $form.Tag['Xccdf'].Text | Should -BeExactly ''
                $form.Tag['ContentPath'].Text | Should -BeExactly ''
                @($form.Tag['Profiles'].Items).Count | Should -Be 1
            } finally { $form.Dispose() }
        }
        Should -Invoke -ModuleName woscap Show-WoscapGuiMessage -Times 0 -Scope It
    }

    It 'keeps the defaults, shows no dialog and does not throw for a <Case> file' -ForEach @(
        @{ Case = 'missing'; Text = $null }
        @{ Case = 'empty'; Text = '' }
        @{ Case = 'corrupt'; Text = '{ "Version": 1, "Targets": ' }
        @{ Case = 'wrong-Version'; Text = '{ "Version": 9, "Targets": "x", "ThrottleLimit": 3 }' }
        @{ Case = 'unreadable'; Text = '{ "Version": 1, "Targets": "x" }'; ReadThrows = $true }
    ) {
        if ($null -ne $Text) {
            New-Item -ItemType Directory -Path (Split-Path $script:SettingsFile -Parent) -Force | Out-Null
            [System.IO.File]::WriteAllText($script:SettingsFile, $Text)
        }
        if ($ReadThrows) { Mock -ModuleName woscap Get-Content { throw 'access denied' } }
        InModuleScope woscap {
            $form = $null
            { $script:form = New-WoscapMainForm } | Should -Not -Throw
            $form = $script:form
            try {
                $t = $form.Tag
                $defaults = $t['SettingsDefaults']
                $defaults | Should -Not -BeNullOrEmpty
                $t['Targets'].Text | Should -BeExactly ''
                $t['ThrottleLimit'].Value | Should -Be (Get-WoscapGuiScanDefault).ThrottleLimit
                $t['Benchmark'].SelectedItem | Should -Be 'Windows11'
                $t['Status'].Text | Should -BeExactly ''
                $form.StartPosition | Should -Be 'CenterScreen'
            } finally { $form.Dispose() }
        }
        Should -Invoke -ModuleName woscap Show-WoscapGuiMessage -Times 0 -Scope It
    }

    It 'captures SettingsDefaults from the controls before import' {
        Save-TestSettings @{ Targets = 'saved-host'; ThrottleLimit = 3 }
        InModuleScope woscap {
            $form = New-WoscapMainForm
            try {
                $form.Tag['Targets'].Text | Should -Be 'saved-host'
                $d = $form.Tag['SettingsDefaults']
                $d.Targets | Should -BeExactly ''
                $d.ThrottleLimit | Should -Be (Get-WoscapGuiScanDefault).ThrottleLimit
                @($d.Keys | Sort-Object) | Should -Be @('AdvancedExpanded', 'Benchmark', 'ContentDestination', 'ContentPath',
                    'ExportFormat', 'IntegrationPath', 'JsonPath', 'Profiles', 'Targets', 'ThrottleLimit', 'Window', 'XccdfPath')
            } finally { $form.Dispose() }
        }
    }

    It 'never throws to the form when applying fails' {
        Save-TestSettings @{ Targets = 'x' }
        Mock -ModuleName woscap Resolve-WoscapGuiSettings { throw 'bad' }
        InModuleScope woscap {
            { $script:f = New-WoscapMainForm } | Should -Not -Throw
            $script:f.Dispose()
        }
    }

    Context 'window bounds' {
        It 'applies on-screen bounds' {
            Save-TestSettings @{ Window = @{ X = 100; Y = 80; Width = 1100; Height = 850; Maximized = $false } }
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try {
                    $form.StartPosition | Should -Be 'Manual'
                    $form.Bounds | Should -Be (New-Object System.Drawing.Rectangle(100, 80, 1100, 850))
                    $form.WindowState | Should -Be 'Normal'
                } finally { $form.Dispose() }
            }
        }

        It 'does not apply bounds that are off every screen' {
            Save-TestSettings @{ Window = @{ X = 5000; Y = 5000; Width = 1100; Height = 850; Maximized = $true } }
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try {
                    $form.StartPosition | Should -Be 'CenterScreen'
                    $form.Size | Should -Be (New-Object System.Drawing.Size(900, 700))
                    $form.WindowState | Should -Be 'Normal'
                } finally { $form.Dispose() }
            }
        }

        It 'applies bounds on a second screen' {
            Mock -ModuleName woscap Get-WoscapGuiScreenArea {
                , @((New-Object System.Drawing.Rectangle(0, 0, 1920, 1040)), (New-Object System.Drawing.Rectangle(-1280, 0, 1280, 984)))
            }
            Save-TestSettings @{ Window = @{ X = -1200; Y = 10; Width = 900; Height = 700; Maximized = $false } }
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try { $form.Location | Should -Be (New-Object System.Drawing.Point(-1200, 10)) } finally { $form.Dispose() }
            }
        }

        It 'clamps undersized bounds to MinimumSize' {
            Save-TestSettings @{ Window = @{ X = 10; Y = 10; Width = 100; Height = 50; Maximized = $false } }
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try {
                    $form.Size | Should -Be $form.MinimumSize
                    $form.Location | Should -Be (New-Object System.Drawing.Point(10, 10))
                } finally { $form.Dispose() }
            }
        }

        It 'restores Maximized' {
            Save-TestSettings @{ Window = @{ X = 10; Y = 10; Width = 1000; Height = 800; Maximized = $true } }
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try {
                    $form.WindowState | Should -Be 'Maximized'
                    $form.RestoreBounds | Should -Be (New-Object System.Drawing.Rectangle(10, 10, 1000, 800))
                } finally { $form.Dispose() }
            }
        }

        It 'exports RestoreBounds when the window is maximized' {
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try {
                    $form.StartPosition = 'Manual'
                    $form.Bounds = New-Object System.Drawing.Rectangle(30, 40, 1000, 800)
                    $form.Show(); [System.Windows.Forms.Application]::DoEvents()
                    $form.WindowState = 'Maximized'; [System.Windows.Forms.Application]::DoEvents()
                    $form.Bounds | Should -Not -Be (New-Object System.Drawing.Rectangle(30, 40, 1000, 800))
                    Export-WoscapGuiSettings -Tag $form.Tag -Form $form
                } finally { $form.Close(); $form.Dispose() }
                $w = (Read-WoscapGuiSettingsFile)['Window']
                [int]$w.X | Should -Be 30
                [int]$w.Y | Should -Be 40
                [int]$w.Width | Should -Be 1000
                [int]$w.Height | Should -Be 800
                $w.Maximized | Should -BeTrue
            }
        }
    }

    Context 'FormClosing' {
        It 'calls Export-WoscapGuiSettings with the closing form' {
            Mock -ModuleName woscap Export-WoscapGuiSettings { }
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try {
                    $e = Invoke-FormClosing $form
                    $e.Cancel | Should -BeFalse
                    Should -Invoke Export-WoscapGuiSettings -Times 1 -Exactly -Scope It -ParameterFilter { $Form -is [System.Windows.Forms.Form] -and [object]::ReferenceEquals($Form.Tag, $Tag) }
                } finally { $form.Dispose() }
            }
        }

        It 'never cancels the close when Export throws' {
            Mock -ModuleName woscap Export-WoscapGuiSettings { throw 'disk gone' }
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try {
                    $script:e = $null
                    { $script:e = Invoke-FormClosing $form } | Should -Not -Throw
                    $script:e.Cancel | Should -BeFalse
                } finally { $form.Dispose() }
            }
        }

        It 'warns and does not cancel when the save fails' {
            Mock -ModuleName woscap Move-Item { throw 'locked' }
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try {
                    $e = Invoke-FormClosing $form 3>$null
                    $e.Cancel | Should -BeFalse
                } finally { $form.Dispose() }
            }
            Test-Path -LiteralPath $script:SettingsFile | Should -BeFalse
        }

        It 'saves through a real Show and Close' {
            InModuleScope woscap {
                $form = New-WoscapMainForm
                $form.Tag['Targets'].Text = 'closed-host'
                $form.Show(); [System.Windows.Forms.Application]::DoEvents()
                $form.Close(); $form.Dispose()
            }
            (Get-Content -LiteralPath $script:SettingsFile -Raw | ConvertFrom-Json).Targets | Should -Be 'closed-host'
        }
    }

    Context 'Reset settings' {
        BeforeEach {
            # Every field away from its default, so a reset has something to undo.
            Save-TestSettings @{
                Benchmark = 'Edge'; XccdfPath = $script:Xccdf; Targets = 'saved-host'; Profiles = @($script:ProfB, $script:ProfA)
                AdvancedExpanded = $true; ContentPath = $script:Dir; ThrottleLimit = 3; JsonPath = (Join-Path $script:Dir 'o.json')
                ExportFormat = 'Html'; ContentDestination = $script:Dir; IntegrationPath = $script:Dir
                Window = @{ X = 20; Y = 30; Width = 1200; Height = 900; Maximized = $true }
            }
        }

        It 'is a File menu item mapped as MenuResetSettings, next to Export and Exit' {
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try {
                    $item = $form.Tag['MenuResetSettings']
                    $item | Should -BeOfType [System.Windows.Forms.ToolStripMenuItem]
                    $item.Text | Should -Be 'Reset &settings...'
                    $item.OwnerItem.Text | Should -Be '&File'
                } finally { $form.Dispose() }
            }
        }

        It 'menu click asks through the message seam with Yes/No' {
            Mock -ModuleName woscap Show-WoscapGuiMessage { $false }
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try { $form.Tag['MenuResetSettings'].PerformClick() } finally { $form.Dispose() }
            }
            Should -Invoke -ModuleName woscap Show-WoscapGuiMessage -Times 1 -Exactly -Scope It -ParameterFilter { $YesNo }
        }

        It 'changes nothing and keeps the file when the answer is <Shown>' -ForEach @(
            @{ Shown = 'No'; Answer = $false }
            @{ Shown = 'a closed or mocked dialog ($null)'; Answer = $null }
            @{ Shown = 'a non-bool truthy value'; Answer = 'Yes' }
        ) {
            $script:answer = $Answer
            Mock -ModuleName woscap Show-WoscapGuiMessage { $script:answer }
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try {
                    $before = Get-WoscapGuiSettingsState -Tag $form.Tag -Form $form
                    Reset-WoscapGuiSettings -Tag $form.Tag -Form $form | Should -BeFalse
                    $after = Get-WoscapGuiSettingsState -Tag $form.Tag -Form $form
                    ($after | ConvertTo-Json -Depth 4) | Should -Be ($before | ConvertTo-Json -Depth 4)
                    $form.Tag['Targets'].Text | Should -Be 'saved-host'
                } finally { $form.Dispose() }
            }
            Test-Path -LiteralPath $script:SettingsFile | Should -BeTrue
        }

        It 'deletes the file and returns every field to SettingsDefaults when confirmed' {
            Mock -ModuleName woscap Show-WoscapGuiMessage { $true }
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try {
                    $form.Tag['Targets'].Text | Should -Be 'saved-host'
                    $form.WindowState | Should -Be 'Maximized'
                    Reset-WoscapGuiSettings -Tag $form.Tag -Form $form | Should -BeTrue
                    Test-Path -LiteralPath (Get-WoscapGuiSettingsPath) | Should -BeFalse
                    $d = $form.Tag['SettingsDefaults']
                    $now = Get-WoscapGuiSettingsState -Tag $form.Tag -Form $form
                    foreach ($k in @($d.Keys | Where-Object { $_ -ne 'Window' })) {
                        ($now[$k] | ConvertTo-Json -Compress) | Should -Be ($d[$k] | ConvertTo-Json -Compress) -Because $k
                    }
                    $now.Window.Width | Should -Be $d.Window.Width
                    $now.Window.Height | Should -Be $d.Window.Height
                    $now.Window.Maximized | Should -BeFalse
                    # Centered on the (mocked) 1920x1040 screen, as CenterScreen would place it.
                    $now.Window.X | Should -Be ([int][Math]::Floor((1920 - $d.Window.Width) / 2))
                    $now.Window.Y | Should -Be ([int][Math]::Floor((1040 - $d.Window.Height) / 2))
                    # Derived UI follows, as after user edits.
                    $form.Tag['AdvancedGroup'].Visible | Should -BeFalse
                    $form.Tag['AdvancedToggle'].Text | Should -Be '[+] Advanced'
                    $form.Tag['ContentPathDefault'].Text | Should -Match 'Windows11$'
                    $form.Tag['ProfileRemove'].Enabled | Should -BeFalse
                } finally { $form.Dispose() }
            }
        }

        It 'still resets the fields, with a warning, when the delete fails' {
            Mock -ModuleName woscap Show-WoscapGuiMessage { $true }
            Mock -ModuleName woscap Remove-Item { throw 'locked' }
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try {
                    { $script:r = Reset-WoscapGuiSettings -Tag $form.Tag -Form $form -WarningAction SilentlyContinue } | Should -Not -Throw
                    $form.Tag['Targets'].Text | Should -BeExactly ''
                } finally { $form.Dispose() }
            }
        }

        It 'saves the defaults again on the next close' {
            Mock -ModuleName woscap Show-WoscapGuiMessage { $true }
            InModuleScope woscap {
                $form = New-WoscapMainForm
                try {
                    [void](Reset-WoscapGuiSettings -Tag $form.Tag -Form $form)
                    [void](Invoke-FormClosing $form)
                } finally { $form.Dispose() }
            }
            (Get-Content -LiteralPath $script:SettingsFile -Raw | ConvertFrom-Json).Targets | Should -BeExactly ''
        }
    }
}

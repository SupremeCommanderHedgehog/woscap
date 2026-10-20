BeforeDiscovery {
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms
    $script:ModuleRoot = Split-Path $PSScriptRoot -Parent | Split-Path -Parent
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'GUI shell helpers' -Skip:(-not $script:IsSta) {
    BeforeEach {
        $tabs = New-Object System.Windows.Forms.TabControl
        $scanTab = New-Object System.Windows.Forms.TabPage
        $otherTab = New-Object System.Windows.Forms.TabPage
        $tabs.TabPages.AddRange(@($otherTab, $scanTab))
        $bench = New-Object System.Windows.Forms.ComboBox
        [void]$bench.Items.Add('Windows11'); $bench.SelectedIndex = 0
        $script:tag = @{
            Run = New-Object System.Windows.Forms.Button
            MenuRun = New-Object System.Windows.Forms.ToolStripMenuItem
            Export = New-Object System.Windows.Forms.Button
            MenuExport = New-Object System.Windows.Forms.ToolStripMenuItem
            AdvancedToggle = New-Object System.Windows.Forms.Button
            AdvancedGroup = New-Object System.Windows.Forms.GroupBox
            AdvancedExpanded = $false
            Tabs = $tabs; ScanTab = $scanTab
            ContentPathDefault = New-Object System.Windows.Forms.Label
            Benchmark = $bench
        }
    }
    AfterEach { $script:tag['Tabs'].Dispose() }

    It 'keeps a button and its menu item enabled in lockstep' {
        InModuleScope woscap -Parameters @{ Tag = $script:tag } {
            param($Tag)
            Set-WoscapGuiActionEnabled -Tag $Tag -Action Run -Enabled $false
            $Tag['Run'].Enabled     | Should -BeFalse
            $Tag['MenuRun'].Enabled | Should -BeFalse
            Set-WoscapGuiActionEnabled -Tag $Tag -Action Export -Enabled $true
            $Tag['Export'].Enabled     | Should -BeTrue
            $Tag['MenuExport'].Enabled | Should -BeTrue
        }
    }
    It 'expands and collapses the Advanced group' {
        InModuleScope woscap -Parameters @{ Tag = $script:tag } {
            param($Tag)
            Set-WoscapGuiAdvanced -Tag $Tag -Expanded $true
            $Tag['AdvancedExpanded']    | Should -BeTrue
            $Tag['AdvancedToggle'].Text | Should -Be '[-] Advanced'
            Set-WoscapGuiAdvanced -Tag $Tag -Expanded $false
            $Tag['AdvancedExpanded']    | Should -BeFalse
            $Tag['AdvancedToggle'].Text | Should -Be '[+] Advanced'
        }
    }
    It 'Show-WoscapGuiAdvancedOption selects the Scan tab and expands Advanced' {
        InModuleScope woscap -Parameters @{ Tag = $script:tag } {
            param($Tag)
            $Tag['Tabs'].SelectedIndex = 0
            Show-WoscapGuiAdvancedOption -Tag $Tag
            $Tag['Tabs'].SelectedTab | Should -Be $Tag['ScanTab']
            $Tag['AdvancedExpanded'] | Should -BeTrue
        }
    }
    It 'shows the default content path for the selected benchmark' {
        InModuleScope woscap -Parameters @{ Tag = $script:tag } {
            param($Tag)
            Update-WoscapGuiContentHint -Tag $Tag
            $expected = Join-Path $script:WoscapModuleRoot (Join-Path 'Content' 'Windows11')
            $Tag['ContentPathDefault'].Text | Should -Be "Default: $expected"
        }
    }
    It 'About reports the module version from the manifest' {
        $version = (Import-PowerShellDataFile (Join-Path $script:ModuleRoot 'woscap.psd1')).ModuleVersion
        InModuleScope woscap -Parameters @{ Version = $version } {
            param($Version)
            $script:aboutText = $null
            Mock Show-WoscapGuiMessage { $script:aboutText = $Text }
            Show-WoscapGuiAbout
            $script:aboutText | Should -Match ([regex]::Escape($Version))
        }
    }
    It 'Open manual opens MANUAL.md when present' {
        InModuleScope woscap {
            Mock Invoke-Item { }
            Mock Show-WoscapGuiMessage { }
            Open-WoscapGuiManual
            Should -Invoke Invoke-Item -Times 1 -Exactly -ParameterFilter { $LiteralPath -like '*MANUAL.md' }
            Should -Not -Invoke Show-WoscapGuiMessage
        }
    }
    It 'Open manual shows a message instead when the file is missing' {
        InModuleScope woscap {
            Mock Invoke-Item { }
            Mock Show-WoscapGuiMessage { }
            Open-WoscapGuiManual -Path 'C:\does\not\exist\MANUAL.md'
            Should -Not -Invoke Invoke-Item
            Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly
        }
    }
}

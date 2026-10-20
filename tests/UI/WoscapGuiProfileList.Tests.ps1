BeforeDiscovery {
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Profile list helpers' -Skip:(-not $script:IsSta) {
    BeforeEach {
        $script:tag = @{
            Profiles      = New-Object System.Windows.Forms.ListBox
            ProfileRemove = New-Object System.Windows.Forms.Button
            ProfileUp     = New-Object System.Windows.Forms.Button
            ProfileDown   = New-Object System.Windows.Forms.Button
        }
    }
    AfterEach { foreach ($c in $script:tag.Values) { $c.Dispose() } }

    It 'adds paths in order and skips case-insensitive duplicates' {
        InModuleScope woscap -Parameters @{ Tag = $script:tag } {
            param($Tag)
            Add-WoscapGuiProfile -Tag $Tag -Path @('C:\a.psd1', 'C:\b.psd1')
            Add-WoscapGuiProfile -Tag $Tag -Path @('c:\A.PSD1', 'C:\c.psd1')
            @($Tag['Profiles'].Items) | Should -Be @('C:\a.psd1', 'C:\b.psd1', 'C:\c.psd1')
        }
    }
    It 'removes the selected profile and keeps a sensible selection' {
        InModuleScope woscap -Parameters @{ Tag = $script:tag } {
            param($Tag)
            Add-WoscapGuiProfile -Tag $Tag -Path @('C:\a.psd1', 'C:\b.psd1', 'C:\c.psd1')
            $Tag['Profiles'].SelectedIndex = 2
            Remove-WoscapGuiProfile -Tag $Tag
            @($Tag['Profiles'].Items) | Should -Be @('C:\a.psd1', 'C:\b.psd1')
            $Tag['Profiles'].SelectedIndex | Should -Be 1
        }
    }
    It 'is a no-op to remove with nothing selected' {
        InModuleScope woscap -Parameters @{ Tag = $script:tag } {
            param($Tag)
            Add-WoscapGuiProfile -Tag $Tag -Path @('C:\a.psd1')
            $Tag['Profiles'].SelectedIndex = -1
            Remove-WoscapGuiProfile -Tag $Tag
            @($Tag['Profiles'].Items).Count | Should -Be 1
        }
    }
    It 'moves the selected profile up and down, and clamps at the ends' {
        InModuleScope woscap -Parameters @{ Tag = $script:tag } {
            param($Tag)
            Add-WoscapGuiProfile -Tag $Tag -Path @('C:\a.psd1', 'C:\b.psd1', 'C:\c.psd1')
            $Tag['Profiles'].SelectedIndex = 2
            Move-WoscapGuiProfile -Tag $Tag -Offset -1
            @($Tag['Profiles'].Items) | Should -Be @('C:\a.psd1', 'C:\c.psd1', 'C:\b.psd1')
            $Tag['Profiles'].SelectedIndex | Should -Be 1
            $Tag['Profiles'].SelectedIndex = 0
            Move-WoscapGuiProfile -Tag $Tag -Offset -1
            @($Tag['Profiles'].Items) | Should -Be @('C:\a.psd1', 'C:\c.psd1', 'C:\b.psd1')
        }
    }
    It 'enables Remove/Up/Down only when the action is possible' {
        InModuleScope woscap -Parameters @{ Tag = $script:tag } {
            param($Tag)
            Update-WoscapGuiProfileButton -Tag $Tag
            $Tag['ProfileRemove'].Enabled | Should -BeFalse
            Add-WoscapGuiProfile -Tag $Tag -Path @('C:\a.psd1', 'C:\b.psd1')
            $Tag['Profiles'].SelectedIndex = 0
            Update-WoscapGuiProfileButton -Tag $Tag
            $Tag['ProfileRemove'].Enabled | Should -BeTrue
            $Tag['ProfileUp'].Enabled     | Should -BeFalse
            $Tag['ProfileDown'].Enabled   | Should -BeTrue
            $Tag['Profiles'].SelectedIndex = 1
            Update-WoscapGuiProfileButton -Tag $Tag
            $Tag['ProfileUp'].Enabled     | Should -BeTrue
            $Tag['ProfileDown'].Enabled   | Should -BeFalse
        }
    }
}

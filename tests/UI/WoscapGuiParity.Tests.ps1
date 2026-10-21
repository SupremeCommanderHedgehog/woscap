BeforeDiscovery {
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
    $root = Split-Path $PSScriptRoot -Parent | Split-Path -Parent
    Import-Module (Join-Path $root 'woscap.psd1') -Force
    $script:Manifest = Import-PowerShellDataFile (Join-Path $root 'Private/UI/WoscapGuiParity.psd1')
    $common = @([System.Management.Automation.PSCmdlet]::CommonParameters) +
              @([System.Management.Automation.PSCmdlet]::OptionalCommonParameters)
    $script:Cmdlets = @(Get-Command -Module woscap | Where-Object Name -ne 'Show-WoscapGui' | Sort-Object Name | ForEach-Object {
        @{ Name = $_.Name; Params = @($_.Parameters.Keys | Where-Object { $_ -notin $common } | Sort-Object) }
    })
    # GuiOnly is the one reserved non-cmdlet key: GUI items with no cmdlet parameter.
    $script:GuiOnly = @(if ($script:Manifest.ContainsKey('GuiOnly')) {
        foreach ($k in $script:Manifest['GuiOnly'].Keys) { @{ Key = $k; Reason = $script:Manifest['GuiOnly'][$k] } }
    })
    $script:Entries = @(foreach ($cmd in @($script:Manifest.Keys | Where-Object { $_ -ne 'GuiOnly' })) {
        foreach ($p in $script:Manifest[$cmd].Keys) {
            @{ Cmdlet = $cmd; Param = $p; Entry = $script:Manifest[$cmd][$p] }
        }
    })
}
BeforeAll {
    $root = Split-Path $PSScriptRoot -Parent | Split-Path -Parent
    Import-Module (Join-Path $root 'woscap.psd1') -Force
    $script:Manifest = Import-PowerShellDataFile (Join-Path $root 'Private/UI/WoscapGuiParity.psd1')
    Add-Type -AssemblyName System.Windows.Forms
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'GUI / CLI parity manifest' {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    It 'covers exactly the exported cmdlets (except Show-WoscapGui)' {
        # Discovery-phase variables are not visible at run time; recompute here.
        $exported = @(Get-Command -Module woscap | Where-Object Name -ne 'Show-WoscapGui' | ForEach-Object Name | Sort-Object)
        @($script:Manifest.Keys | Where-Object { $_ -ne 'GuiOnly' } | Sort-Object) | Should -Be $exported
    }

    It '<Name>: every parameter is declared and none are stale' -ForEach $script:Cmdlets {
        $declared = @($script:Manifest[$Name].Keys | Sort-Object)
        $missing = @($Params | Where-Object { $_ -notin $declared })
        $stale   = @($declared | Where-Object { $_ -notin $Params })
        $missing | Should -BeNullOrEmpty -Because "$Name parameters need a GUI control or a CliOnly reason in WoscapGuiParity.psd1 (missing: $($missing -join ', '))"
        $stale   | Should -BeNullOrEmpty -Because "$Name no longer has these parameters (stale: $($stale -join ', '))"
    }

    It '<Cmdlet> -<Param>: has exactly one of Control / CliOnly' -ForEach $script:Entries {
        $hasControl = $Entry.ContainsKey('Control') -and -not [string]::IsNullOrWhiteSpace($Entry.Control)
        $hasCliOnly = $Entry.ContainsKey('CliOnly') -and -not [string]::IsNullOrWhiteSpace($Entry.CliOnly)
        ($hasControl -xor $hasCliOnly) | Should -BeTrue
    }

    It '<Cmdlet> -<Param>: mapped control exists on the main form' -ForEach @($script:Entries | Where-Object { $_.Entry.ContainsKey('Control') }) -Skip:(-not $script:IsSta) {
        InModuleScope woscap -Parameters @{ Control = $Entry.Control } {
            param($Control)
            $form = New-WoscapMainForm
            try { $form.Tag.ContainsKey($Control) | Should -BeTrue -Because "Tag has no '$Control'" }
            finally { $form.Dispose() }
        }
    }

    It 'maps the GUI-only Reset settings menu item' {
        $script:Manifest.ContainsKey('GuiOnly') | Should -BeTrue
        $script:Manifest['GuiOnly'].ContainsKey('MenuResetSettings') | Should -BeTrue
    }

    It 'has no Pending entries' {
        $text = Get-Content (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'Private/UI/WoscapGuiParity.psd1') -Raw
        $text | Should -Not -Match 'Pending'
    }

    It 'GuiOnly <Key>: exists on the main form and states a reason' -ForEach $script:GuiOnly {
        $Reason | Should -BeOfType [string]
        [string]::IsNullOrWhiteSpace($Reason) | Should -BeFalse
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Set-ItResult -Skipped -Because 'WinForms needs STA'; return }
        InModuleScope woscap -Parameters @{ Key = $Key } {
            param($Key)
            $form = New-WoscapMainForm
            try { $form.Tag.ContainsKey($Key) | Should -BeTrue -Because "Tag has no '$Key'" }
            finally { $form.Dispose() }
        }
    }
}

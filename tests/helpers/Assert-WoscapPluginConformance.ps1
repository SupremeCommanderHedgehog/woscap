# Shared Pester assertion: dot-source this file, then call
# Assert-WoscapPluginConformance -Path <plugin folder>. Must run inside a woscap
# module scope (the caller wraps it in InModuleScope woscap) so it can load the plugin.
function Assert-WoscapPluginConformance {
    param([Parameter(Mandatory)] [string] $Path)

    $manifestPath = Join-Path $Path 'plugin.psd1'
    Test-Path -LiteralPath $manifestPath | Should -BeTrue -Because "plugin.psd1 must exist at $Path"
    $manifest = Import-PowerShellDataFile -LiteralPath $manifestPath

    [string]$manifest.Name | Should -Not -BeNullOrEmpty
    @($manifest.Capabilities).Count | Should -BeGreaterThan 0

    $loaded = Import-WoscapPlugin -Path $Path
    $loaded | Should -Not -BeNullOrEmpty -Because "a conformant plugin must load without warning"
    foreach ($cap in @($manifest.Capabilities)) {
        $loaded.Hooks[$cap] | Should -BeOfType [scriptblock]
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Plugins = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/plugins'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapIntegration' {
    It 'is exported as a public command' {
        Get-Command Get-WoscapIntegration -Module woscap | Should -Not -BeNullOrEmpty
    }
    It 'lists conformant plugins under a given root with Conformant=$true' {
        $good = Get-WoscapIntegration -Path (Join-Path $script:Plugins 'Good') -WarningAction SilentlyContinue |
            Where-Object Name -eq 'Good'
        # -Path may be a single plugin folder or a root; here point at the plugins root:
        $all = Get-WoscapIntegration -Path $script:Plugins -WarningAction SilentlyContinue
        ($all | Where-Object Name -eq 'Good').Conformant | Should -BeTrue
    }
    It 'accepts a single plugin folder and returns just that plugin' {
        $one = @(Get-WoscapIntegration -Path (Join-Path $script:Plugins 'Good') -WarningAction SilentlyContinue)
        $one.Count | Should -Be 1
        $one[0].Name | Should -Be 'Good'
        $one[0].Conformant | Should -BeTrue
    }
    It 'lists a malformed plugin with Conformant=$false rather than hiding it' {
        $all = Get-WoscapIntegration -Path $script:Plugins -WarningAction SilentlyContinue
        ($all | Where-Object Name -eq 'MissingHook').Conformant | Should -BeFalse
    }
}

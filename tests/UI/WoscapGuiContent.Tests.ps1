BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Resolve-WoscapGuiDisaTerms' {
    BeforeEach {
        $script:Cache = Join-Path $TestDrive ('cache-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Cache | Out-Null
    }

    It 'proceeds without a switch or a dialog when the marker exists' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            Write-WoscapDisaTermsMarker -CacheRoot $Cache
            Mock Show-WoscapGuiDisaTermsDialog { throw 'dialog must not be shown' }
            $r = Resolve-WoscapGuiDisaTerms -CacheRoot $Cache
            $r.Proceed      | Should -BeTrue
            $r.AcceptSwitch | Should -BeFalse
            $r.Remember     | Should -BeFalse
            Should -Invoke Show-WoscapGuiDisaTermsDialog -Times 0 -Exactly
        }
    }

    It 'does not proceed when the dialog is cancelled' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            Mock Show-WoscapGuiDisaTermsDialog { $null }
            $r = Resolve-WoscapGuiDisaTerms -CacheRoot $Cache
            $r.Proceed      | Should -BeFalse
            $r.AcceptSwitch | Should -BeFalse
            $r.Remember     | Should -BeFalse
        }
    }

    It 'fails closed when the dialog throws' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            Mock Show-WoscapGuiDisaTermsDialog { throw 'boom' }
            $r = Resolve-WoscapGuiDisaTerms -CacheRoot $Cache
            $r.Proceed | Should -BeFalse
            $r.AcceptSwitch | Should -BeFalse
            $r['Error'] | Should -Match 'boom' -Because 'the caller must show the failure, not a silent cancel'
        }
    }

    It 'accepts with Remember=<remember> and passes the switch' -ForEach @(
        @{ remember = $false }, @{ remember = $true }
    ) {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache; Remember = $remember } {
            param($Cache, $Remember)
            Mock Show-WoscapGuiDisaTermsDialog { @{ Remember = $Remember } }.GetNewClosure()
            $r = Resolve-WoscapGuiDisaTerms -CacheRoot $Cache
            $r.Proceed      | Should -BeTrue
            $r.AcceptSwitch | Should -BeTrue
            $r.Remember     | Should -Be $Remember
            Should -Invoke Show-WoscapGuiDisaTermsDialog -Times 1 -Exactly -ParameterFilter { $Notice -ceq (Get-WoscapDisaNotice) }
        }
    }

    It 'never writes the marker itself' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            Mock Show-WoscapGuiDisaTermsDialog { @{ Remember = $true } }
            $null = Resolve-WoscapGuiDisaTerms -CacheRoot $Cache
            (Get-WoscapDisaMarkerPath -CacheRoot $Cache) | Should -Not -Exist
        }
    }
}

Describe 'Show-WoscapGuiDisaTermsDialog seam' {
    # The real dialog is modal; a stand-in form keeps the seam testable without ShowDialog.
    It 'returns <Expect> for DialogResult <Result>' -ForEach @(
        @{ Result = 'Cancel'; Remember = $true;  Expect = 'null' }
        @{ Result = 'OK';     Remember = $false; Expect = 'Remember=False' }
        @{ Result = 'OK';     Remember = $true;  Expect = 'Remember=True' }
    ) {
        InModuleScope woscap -Parameters @{ Result = $Result; Remember = $Remember; Expect = $Expect } {
            param($Result, $Remember, $Expect)
            $fake = [pscustomobject]@{ Tag = @{ Remember = [pscustomobject]@{ Checked = $Remember } }; Result = $Result; Disposed = $false }
            $fake | Add-Member ScriptMethod ShowDialog { [System.Windows.Forms.DialogResult]$this.Result }
            $fake | Add-Member ScriptMethod Dispose { $this.Disposed = $true }
            Mock New-WoscapGuiDisaTermsDialog { $fake }.GetNewClosure()
            $r = Show-WoscapGuiDisaTermsDialog -Notice 'x'
            $got = if ($null -eq $r) { 'null' } else { 'Remember=' + $r['Remember'] }
            $got | Should -Be $Expect
            $fake.Disposed | Should -BeTrue
            Should -Invoke New-WoscapGuiDisaTermsDialog -Times 1 -Exactly -ParameterFilter { $Notice -eq 'x' }
        }
    }
}

Describe 'Get-WoscapGuiRemoveScope' {
    It 'returns Benchmark and Revision for a revision row' {
        InModuleScope woscap {
            $s = Get-WoscapGuiRemoveScope -Row ([pscustomobject]@{ Benchmark = 'Edge'; Revision = '2' })
            $s.Benchmark | Should -Be 'Edge'
            $s.Revision  | Should -Be '2'
            $s.Keys.Count | Should -Be 2
        }
    }
    It 'returns Benchmark only for AllRevisions' {
        InModuleScope woscap {
            $s = Get-WoscapGuiRemoveScope -Row ([pscustomobject]@{ Benchmark = 'Edge'; Revision = '2' }) -AllRevisions
            $s.Benchmark | Should -Be 'Edge'
            $s.ContainsKey('Revision') | Should -BeFalse
        }
    }
    It 'throws for a row without a usable Benchmark (<name>)' -ForEach @(
        @{ name = 'missing';    row = [pscustomobject]@{ Revision = '2' } }
        @{ name = 'empty';      row = [pscustomobject]@{ Benchmark = '';   Revision = '2' } }
        @{ name = 'whitespace'; row = [pscustomobject]@{ Benchmark = '  '; Revision = '2' } }
        @{ name = 'null row';   row = $null }
    ) {
        InModuleScope woscap -Parameters @{ Row = $row } {
            param($Row)
            { Get-WoscapGuiRemoveScope -Row $Row -AllRevisions } | Should -Throw
            { Get-WoscapGuiRemoveScope -Row $Row } | Should -Throw
        }
    }
    It 'throws for a single-revision scope when the Revision is blank or missing' {
        InModuleScope woscap {
            { Get-WoscapGuiRemoveScope -Row ([pscustomobject]@{ Benchmark = 'Edge' }) } | Should -Throw
            { Get-WoscapGuiRemoveScope -Row ([pscustomobject]@{ Benchmark = 'Edge'; Revision = '' }) } | Should -Throw
        }
    }
    It 'splats into a Remove-WoscapBenchmark-shaped call' {
        InModuleScope woscap {
            function Test-Splat { param($Benchmark, $Revision) "$Benchmark|$Revision" }
            $s = Get-WoscapGuiRemoveScope -Row ([pscustomobject]@{ Benchmark = 'Edge'; Revision = '2' })
            Test-Splat @s | Should -Be 'Edge|2'
        }
    }
}

Describe 'Find-WoscapGuiContentPack' {
    It 'matches case-insensitively and returns the pack name as listed' {
        InModuleScope woscap {
            Find-WoscapGuiContentPack -Benchmark 'edge' -Available @('Chrome', 'Edge', 'Windows11') | Should -BeExactly 'Edge'
        }
    }
    It 'returns $null for no exact match (<b>)' -ForEach @(
        @{ b = 'Firewall' }, @{ b = 'Edg' }, @{ b = 'Edge2' }, @{ b = '' }, @{ b = $null }
    ) {
        InModuleScope woscap -Parameters @{ B = $b } {
            param($B)
            Find-WoscapGuiContentPack -Benchmark $B -Available @('Chrome', 'Edge', 'Windows11') | Should -BeNullOrEmpty
        }
    }
    It 'returns $null for an empty or null list' {
        InModuleScope woscap {
            Find-WoscapGuiContentPack -Benchmark 'Edge' -Available @() | Should -BeNullOrEmpty
            Find-WoscapGuiContentPack -Benchmark 'Edge' -Available $null | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-WoscapGuiContentDestination' {
    BeforeEach {
        $script:Box = New-Object System.Windows.Forms.TextBox
        $script:Tag = @{ ContentDestination = $script:Box }
    }
    It 'returns $null for blank or whitespace text (<t>)' -ForEach @(
        @{ t = '' }, @{ t = '   ' }, @{ t = "`t " }
    ) {
        $script:Box.Text = $t
        InModuleScope woscap -Parameters @{ Tag = $script:Tag } {
            param($Tag)
            Get-WoscapGuiContentDestination -Tag $Tag | Should -BeNullOrEmpty
        }
    }
    It 'returns the trimmed path' {
        $script:Box.Text = '  C:\some folder\cache  '
        InModuleScope woscap -Parameters @{ Tag = $script:Tag } {
            param($Tag)
            Get-WoscapGuiContentDestination -Tag $Tag | Should -BeExactly 'C:\some folder\cache'
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:SpecFields = @('Benchmark', 'XccdfPath', 'Targets', 'Profiles', 'AdvancedExpanded', 'ContentPath',
        'ThrottleLimit', 'JsonPath', 'ExportFormat', 'ContentDestination', 'IntegrationPath', 'Window') | Sort-Object
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'GUI settings file' {
    BeforeAll {
        # Never the real %LOCALAPPDATA%: every read and write goes to TestDrive.
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }
    }
    BeforeEach {
        Remove-Item -LiteralPath (Join-Path $TestDrive 'woscap') -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'resolves its path under TestDrive while mocked' {
        InModuleScope woscap { Get-WoscapGuiSettingsPath } | Should -BeLike "$TestDrive*"
    }

    It 'returns $null for a <Case> file' -ForEach @(
        @{ Case = 'missing'; Text = $null }
        @{ Case = 'empty'; Text = '' }
        @{ Case = 'whitespace'; Text = "  `r`n " }
        @{ Case = 'corrupt'; Text = '{ "Version": 1, ' }
        @{ Case = 'non-object'; Text = '[1, 2]' }
        @{ Case = 'Version 2'; Text = '{ "Version": 2, "Targets": "a" }' }
        @{ Case = 'Version-less'; Text = '{ "Targets": "a" }' }
        @{ Case = 'string Version'; Text = '{ "Version": "1", "Targets": "a" }' }
        @{ Case = 'bool Version'; Text = '{ "Version": true, "Targets": "a" }' }
    ) {
        if ($null -ne $Text) {
            New-Item -ItemType Directory -Path (Join-Path $TestDrive 'woscap') -Force | Out-Null
            [System.IO.File]::WriteAllText((Join-Path $TestDrive 'woscap\gui-settings.json'), $Text)
        }
        InModuleScope woscap { Read-WoscapGuiSettingsFile } | Should -BeNullOrEmpty
    }

    It 'returns $null without throwing when the read itself throws' {
        New-Item -ItemType Directory -Path (Join-Path $TestDrive 'woscap') -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $TestDrive 'woscap\gui-settings.json'), '{ "Version": 1 }')
        Mock -ModuleName woscap Get-Content { throw 'access denied' }
        { InModuleScope woscap { Read-WoscapGuiSettingsFile } } | Should -Not -Throw
        InModuleScope woscap { Read-WoscapGuiSettingsFile } | Should -BeNullOrEmpty
    }

    It 'round-trips every field type through write then read' {
        $settings = @{
            Benchmark = 'Windows11'; XccdfPath = 'C:\x\y.xml'; Targets = 'h1, h2'
            Profiles = @('C:\p\b.psd1', 'C:\p\a.psd1'); AdvancedExpanded = $true; ContentPath = 'C:\c'
            ThrottleLimit = 12; JsonPath = 'C:\out\r.json'; ExportFormat = 'Csv'
            ContentDestination = 'D:\cache'; IntegrationPath = ''
            Window = @{ X = -5; Y = 20; Width = 1000; Height = 800; Maximized = $false }
        }
        $raw = InModuleScope woscap -Parameters @{ S = $settings } {
            param($S)
            Write-WoscapGuiSettingsFile -Settings $S | Should -BeTrue
            Read-WoscapGuiSettingsFile
        }
        $raw | Should -BeOfType [hashtable]
        foreach ($k in 'Benchmark', 'XccdfPath', 'Targets', 'ContentPath', 'JsonPath', 'ExportFormat', 'ContentDestination', 'IntegrationPath') {
            $raw[$k] | Should -BeExactly $settings[$k] -Because $k
        }
        @($raw['Profiles']) | Should -Be @('C:\p\b.psd1', 'C:\p\a.psd1')
        $raw['AdvancedExpanded'] | Should -BeTrue
        [int]$raw['ThrottleLimit'] | Should -Be 12
        $raw['Window'] | Should -BeOfType [hashtable]
        foreach ($k in 'X', 'Y', 'Width', 'Height') { [int]$raw['Window'][$k] | Should -Be $settings.Window[$k] }
        $raw['Window']['Maximized'] | Should -BeFalse
    }

    It 'keeps a single profile and an empty profile list as lists' {
        foreach ($list in @(, @('C:\only.psd1')), @(, @())) {
            $raw = InModuleScope woscap -Parameters @{ L = $list } {
                param($L)
                Write-WoscapGuiSettingsFile -Settings @{ Profiles = $L } | Should -BeTrue
                Read-WoscapGuiSettingsFile
            }
            , $raw['Profiles'] | Should -BeOfType [object[]]
            @($raw['Profiles']).Count | Should -Be @($list).Count
        }
    }

    It 'writes BOM-less UTF-8 JSON with Version 1 and leaves no temp file' {
        InModuleScope woscap { Write-WoscapGuiSettingsFile -Settings @{ Targets = 'a' } } | Should -BeTrue
        $file = Join-Path $TestDrive 'woscap\gui-settings.json'
        $bytes = [System.IO.File]::ReadAllBytes($file)
        $bytes[0] | Should -Not -Be 0xEF
        ([System.IO.File]::ReadAllText($file) | ConvertFrom-Json).Version | Should -Be 1
        Test-Path -LiteralPath "$file.tmp" | Should -BeFalse
    }

    It 'warns, returns $false and leaves no temp file when the replace fails' {
        Mock -ModuleName woscap Move-Item { throw 'locked' }
        $out = InModuleScope woscap {
            $r = Write-WoscapGuiSettingsFile -Settings @{ Targets = 'a' } -WarningVariable w -WarningAction SilentlyContinue
            @{ Result = $r; Warnings = @($w).Count }
        }
        $out.Result | Should -BeFalse
        $out.Warnings | Should -BeGreaterThan 0
        Test-Path -LiteralPath (Join-Path $TestDrive 'woscap\gui-settings.json.tmp') | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $TestDrive 'woscap\gui-settings.json') | Should -BeFalse
    }

    It 'warns and returns $false without throwing when the path seam itself throws' {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { throw 'no profile' }
        { InModuleScope woscap { Write-WoscapGuiSettingsFile -Settings @{} -WarningAction SilentlyContinue } } | Should -Not -Throw
        InModuleScope woscap { Write-WoscapGuiSettingsFile -Settings @{} -WarningAction SilentlyContinue } | Should -BeFalse
    }

    It 'saves exactly the spec field set, never credential, UseCred, result or filter data' {
        $settings = @{
            Benchmark = 'Windows11'; XccdfPath = ''; Targets = ''; Profiles = @(); AdvancedExpanded = $false
            ContentPath = ''; ThrottleLimit = 4; JsonPath = ''; ExportFormat = 'Csv'; ContentDestination = ''
            IntegrationPath = ''; Window = @{ X = 0; Y = 0; Width = 900; Height = 700; Maximized = $false }
            Credential = 'secret'; UseCred = $true; Results = @('r'); FilterSeverity = 'high'; FilterStatus = 'Open'; Find = 'x'
        }
        InModuleScope woscap -Parameters @{ S = $settings } { param($S) Write-WoscapGuiSettingsFile -Settings $S } | Should -BeTrue
        $json = Get-Content -LiteralPath (Join-Path $TestDrive 'woscap\gui-settings.json') -Raw | ConvertFrom-Json
        $names = @($json.PSObject.Properties.Name | Where-Object { $_ -ne 'Version' } | Sort-Object)
        $names | Should -Be $script:SpecFields
        @($json.Window.PSObject.Properties.Name | Sort-Object) | Should -Be @('Height', 'Maximized', 'Width', 'X', 'Y')
    }

    It 'removes the settings file when present and is a no-op when absent' {
        InModuleScope woscap { Write-WoscapGuiSettingsFile -Settings @{ Targets = 'a' } } | Should -BeTrue
        InModuleScope woscap { Remove-WoscapGuiSettingsFile } | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $TestDrive 'woscap\gui-settings.json') | Should -BeFalse
        { InModuleScope woscap { Remove-WoscapGuiSettingsFile } } | Should -Not -Throw
    }

    It 'warns and returns $false when the delete fails' {
        InModuleScope woscap { Write-WoscapGuiSettingsFile -Settings @{ Targets = 'a' } } | Should -BeTrue
        Mock -ModuleName woscap Remove-Item { throw 'locked' }
        InModuleScope woscap { Remove-WoscapGuiSettingsFile -WarningAction SilentlyContinue } | Should -BeFalse
    }
}

Describe 'Resolve-WoscapGuiSettings' {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }
        $script:Allowed = @{
            Benchmark = @('Edge', 'Windows11'); Format = @('Csv', 'Json', 'Html')
            ThrottleMin = 1; ThrottleMax = 64; MinWidth = 760; MinHeight = 560
        }
        $script:Dir = Join-Path $TestDrive 'exists'
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
        $script:File = Join-Path $script:Dir 'b.xml'
        $script:ProfA = Join-Path $script:Dir 'a.psd1'
        $script:ProfB = Join-Path $script:Dir 'b.psd1'
        foreach ($f in $script:File, $script:ProfA, $script:ProfB) { Set-Content -LiteralPath $f -Value 'x' }
        $script:Gone = Join-Path $TestDrive 'gone'
        function script:Resolve-Raw([hashtable] $Raw) {
            InModuleScope woscap -Parameters @{ R = $Raw; A = $script:Allowed } {
                param($R, $A)
                Resolve-WoscapGuiSettings -Raw $R -Allowed $A
            }
        }
    }

    It 'passes every valid field through' {
        $raw = @{
            Benchmark = 'Edge'; XccdfPath = $script:File; Targets = 'h1'; Profiles = @($script:ProfB, $script:ProfA)
            AdvancedExpanded = $true; ContentPath = $script:Dir; ThrottleLimit = [long]8
            JsonPath = (Join-Path $script:Dir 'out.json'); ExportFormat = 'Html'
            ContentDestination = $script:Dir; IntegrationPath = $script:Dir
            Window = @{ X = 10; Y = 20; Width = 1000; Height = 800; Maximized = $true }
            Credential = 'ignored'
        }
        $r = Resolve-Raw $raw
        $r.Cleared | Should -Be 0
        $v = $r.Values
        @($v.Keys | Sort-Object) | Should -Be $script:SpecFields
        $v.Benchmark | Should -Be 'Edge'
        $v.XccdfPath | Should -Be $script:File
        @($v.Profiles) | Should -Be @($script:ProfB, $script:ProfA)
        $v.AdvancedExpanded | Should -BeTrue
        $v.ThrottleLimit | Should -Be 8
        $v.ThrottleLimit | Should -BeOfType [int]
        $v.ExportFormat | Should -Be 'Html'
        $v.Window.Width | Should -Be 1000
        $v.Window.Maximized | Should -BeTrue
    }

    It 'skips <Field> = <Shown>' -ForEach @(
        @{ Field = 'Benchmark'; Value = 'NoSuchPack'; Shown = 'unknown item' }
        @{ Field = 'Benchmark'; Value = 'windows11'; Shown = 'wrong case' }
        @{ Field = 'Benchmark'; Value = 5; Shown = 'int' }
        @{ Field = 'ExportFormat'; Value = 'Pdf'; Shown = 'unknown item' }
        @{ Field = 'ExportFormat'; Value = $true; Shown = 'bool' }
        @{ Field = 'ThrottleLimit'; Value = 0; Shown = 'below minimum' }
        @{ Field = 'ThrottleLimit'; Value = 65; Shown = 'above maximum' }
        @{ Field = 'ThrottleLimit'; Value = '8'; Shown = 'string' }
        @{ Field = 'ThrottleLimit'; Value = 8.5; Shown = 'fraction' }
        @{ Field = 'ThrottleLimit'; Value = $true; Shown = 'bool' }
        @{ Field = 'AdvancedExpanded'; Value = 'true'; Shown = 'string' }
        @{ Field = 'AdvancedExpanded'; Value = 1; Shown = 'int' }
        @{ Field = 'Targets'; Value = ('a' * 4097); Shown = 'over 4096 chars' }
        @{ Field = 'Targets'; Value = 3; Shown = 'int' }
        @{ Field = 'XccdfPath'; Value = 7; Shown = 'int' }
        @{ Field = 'Profiles'; Value = 'C:\one.psd1'; Shown = 'a bare string' }
        @{ Field = 'Window'; Value = 'big'; Shown = 'string' }
        @{ Field = 'Window'; Value = @{ X = 1; Y = 2; Width = 900 }; Shown = 'missing members' }
        @{ Field = 'Window'; Value = @{ X = 1; Y = 2; Width = 900; Height = '700'; Maximized = $false }; Shown = 'string Height' }
        @{ Field = 'Window'; Value = @{ X = 1; Y = 2; Width = 900; Height = 700; Maximized = 'no' }; Shown = 'string Maximized' }
    ) {
        $r = Resolve-Raw @{ $Field = $Value }
        $r.Values.ContainsKey($Field) | Should -BeFalse
        $r.Cleared | Should -Be 0
    }

    It 'accepts Targets of exactly 4096 chars' {
        (Resolve-Raw @{ Targets = ('a' * 4096) }).Values.Targets.Length | Should -Be 4096
    }

    It 'accepts the throttle bounds themselves' {
        (Resolve-Raw @{ ThrottleLimit = 1 }).Values.ThrottleLimit | Should -Be 1
        (Resolve-Raw @{ ThrottleLimit = 64 }).Values.ThrottleLimit | Should -Be 64
    }

    It 'clears and counts a missing <Field> exactly once' -ForEach @(
        @{ Field = 'XccdfPath'; Kind = 'file' }
        @{ Field = 'ContentPath'; Kind = 'dir' }
        @{ Field = 'ContentDestination'; Kind = 'dir' }
        @{ Field = 'IntegrationPath'; Kind = 'dir' }
        @{ Field = 'JsonPath'; Kind = 'parent' }
    ) {
        $missing = if ($Kind -eq 'parent') { Join-Path $script:Gone 'out.json' } else { $script:Gone }
        $r = Resolve-Raw @{ $Field = $missing }
        $r.Values.ContainsKey($Field) | Should -BeFalse
        $r.Cleared | Should -Be 1
    }

    It 'rejects the wrong kind of path for <Field>' -ForEach @(
        @{ Field = 'XccdfPath'; UseDir = $true }
        @{ Field = 'ContentPath'; UseDir = $false }
    ) {
        $p = if ($UseDir) { $script:Dir } else { $script:File }
        $r = Resolve-Raw @{ $Field = $p }
        $r.Values.ContainsKey($Field) | Should -BeFalse
        $r.Cleared | Should -Be 1
    }

    It 'sums the count across fields' {
        $r = Resolve-Raw @{ XccdfPath = $script:Gone; ContentPath = $script:Gone; JsonPath = (Join-Path $script:Gone 'x.json')
            Profiles = @($script:Gone, $script:ProfA) }
        $r.Cleared | Should -Be 4
    }

    It 'keeps an empty <Field> as the default without counting it' -ForEach @(
        @{ Field = 'XccdfPath' }, @{ Field = 'ContentPath' }, @{ Field = 'JsonPath' },
        @{ Field = 'ContentDestination' }, @{ Field = 'IntegrationPath' }
    ) {
        $r = Resolve-Raw @{ $Field = '' }
        $r.Values[$Field] | Should -BeExactly ''
        $r.Cleared | Should -Be 0
    }

    It 'accepts a JsonPath with no parent folder' {
        (Resolve-Raw @{ JsonPath = 'out.json' }).Values.JsonPath | Should -Be 'out.json'
    }

    It 'drops only the missing profiles, keeps order and counts each once' {
        $gone2 = Join-Path $TestDrive 'gone2.psd1'
        $r = Resolve-Raw @{ Profiles = @($script:ProfB, $script:Gone, $script:ProfA, $gone2, '') }
        @($r.Values.Profiles) | Should -Be @($script:ProfB, $script:ProfA)
        $r.Cleared | Should -Be 2
    }

    It 'keeps an empty profile list as an empty list' {
        $r = Resolve-Raw @{ Profiles = @() }
        $r.Values.ContainsKey('Profiles') | Should -BeTrue
        @($r.Values.Profiles).Count | Should -Be 0
    }

    It 'clamps undersized window bounds to the minimum size' {
        $w = (Resolve-Raw @{ Window = @{ X = 0; Y = 0; Width = 100; Height = 50; Maximized = $false } }).Values.Window
        $w.Width | Should -Be 760
        $w.Height | Should -Be 560
    }

    It 'never throws on a hashtable of garbage' {
        { Resolve-Raw @{ Benchmark = $null; Profiles = @($null, 5); Window = $null; ThrottleLimit = $null } } | Should -Not -Throw
        @((Resolve-Raw @{ Profiles = @($null, 5) }).Values.Profiles).Count | Should -Be 0
    }
}

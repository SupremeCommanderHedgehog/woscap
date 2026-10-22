BeforeAll {
    # Guard (spec 4.9): this run must not create or modify the real per-user settings file.
    $script:RealSettings = if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'woscap\gui-settings.json' } else { $null }
    function script:Get-RealSettingsStamp { if ($script:RealSettings -and (Test-Path -LiteralPath $script:RealSettings)) { (Get-Item -LiteralPath $script:RealSettings).LastWriteTimeUtc.Ticks } else { 'absent' } }
    $script:RealBefore = Get-RealSettingsStamp
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
        @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'woscap') -Filter '*.tmp').Count | Should -Be 0
    }

    It 'warns, returns $false and leaves no temp file when the first-time move fails' {
        Mock -ModuleName woscap Move-Item { throw 'locked' }
        $out = InModuleScope woscap {
            $r = Write-WoscapGuiSettingsFile -Settings @{ Targets = 'a' } -WarningVariable w -WarningAction SilentlyContinue
            @{ Result = $r; Warnings = @($w).Count }
        }
        $out.Result | Should -BeFalse
        $out.Warnings | Should -BeGreaterThan 0
        @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'woscap') -Filter '*.tmp').Count | Should -Be 0
        Test-Path -LiteralPath (Join-Path $TestDrive 'woscap\gui-settings.json') | Should -BeFalse
    }

    It 'warns, returns $false, keeps the old file and leaves no temp file when the replace fails' {
        InModuleScope woscap { Write-WoscapGuiSettingsFile -Settings @{ Targets = 'old' } } | Should -BeTrue
        $file = Join-Path $TestDrive 'woscap\gui-settings.json'
        # A read-only target makes File.Replace fail for real.
        (Get-Item -LiteralPath $file).IsReadOnly = $true
        try {
            InModuleScope woscap { Write-WoscapGuiSettingsFile -Settings @{ Targets = 'new' } -WarningAction SilentlyContinue } | Should -BeFalse
            (Get-Content -LiteralPath $file -Raw | ConvertFrom-Json).Targets | Should -Be 'old'
            @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'woscap') -Filter '*.tmp').Count | Should -Be 0
        } finally { (Get-Item -LiteralPath $file).IsReadOnly = $false }
    }

    It 'replaces an existing file in place' {
        InModuleScope woscap { Write-WoscapGuiSettingsFile -Settings @{ Targets = 'first' } } | Should -BeTrue
        InModuleScope woscap { Write-WoscapGuiSettingsFile -Settings @{ Targets = 'second' } } | Should -BeTrue
        (Get-Content -LiteralPath (Join-Path $TestDrive 'woscap\gui-settings.json') -Raw | ConvertFrom-Json).Targets | Should -Be 'second'
        @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'woscap') -Filter '*.tmp').Count | Should -Be 0
    }

    It 'writes through Write-WoscapText to a unique temp file in the same folder' {
        $script:tmpPaths = [System.Collections.Generic.List[string]]::new()
        Mock -ModuleName woscap Write-WoscapText {
            $script:tmpPaths.Add($Path)
            [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
        }
        InModuleScope woscap { Write-WoscapGuiSettingsFile -Settings @{ Targets = 'a' } } | Should -BeTrue
        InModuleScope woscap { Write-WoscapGuiSettingsFile -Settings @{ Targets = 'b' } } | Should -BeTrue
        $script:tmpPaths.Count | Should -Be 2
        $script:tmpPaths[0] | Should -Not -Be $script:tmpPaths[1]
        foreach ($p in $script:tmpPaths) {
            Split-Path $p -Parent | Should -Be (Join-Path $TestDrive 'woscap')
            Split-Path $p -Leaf | Should -BeLike "gui-settings.json.$PID.*.tmp"
        }
    }

    It 'does not corrupt the file when a second writer runs in the middle of the first' {
        # Writer B runs to completion between A writing its temp file and A replacing the target.
        $script:nested = $false
        Mock -ModuleName woscap Write-WoscapText {
            [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
            if (-not $script:nested) {
                $script:nested = $true
                InModuleScope woscap { Write-WoscapGuiSettingsFile -Settings @{ Targets = 'writer-B' } } | Should -BeTrue
            }
        }
        InModuleScope woscap { Write-WoscapGuiSettingsFile -Settings @{ Targets = 'writer-A' } } | Should -BeTrue
        $script:nested | Should -BeTrue
        (Get-Content -LiteralPath (Join-Path $TestDrive 'woscap\gui-settings.json') -Raw | ConvertFrom-Json).Targets | Should -Be 'writer-A'
        @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'woscap') -Filter '*.tmp').Count | Should -Be 0
    }

    It 'saves Targets of exactly the limit' {
        $limit = InModuleScope woscap { $script:WoscapGuiTargetsMaxLength }
        $limit | Should -Be 65536
        InModuleScope woscap -Parameters @{ T = ('a' * 65536) } { param($T) Write-WoscapGuiSettingsFile -Settings @{ Targets = $T } } | Should -BeTrue
        $raw = InModuleScope woscap { Read-WoscapGuiSettingsFile }
        $raw['Targets'].Length | Should -Be 65536
    }

    It 'does not save Targets over the limit, warns, and still saves the rest' {
        $out = InModuleScope woscap -Parameters @{ T = ('a' * 65537) } {
            param($T)
            $r = Write-WoscapGuiSettingsFile -Settings @{ Targets = $T; ThrottleLimit = 5 } -WarningVariable w -WarningAction SilentlyContinue
            @{ Result = $r; Warnings = @($w | ForEach-Object { "$_" }) }
        }
        $out.Result | Should -BeTrue
        ($out.Warnings -join ' ') | Should -Match 'Targets'
        $raw = InModuleScope woscap { Read-WoscapGuiSettingsFile }
        $raw.ContainsKey('Targets') | Should -BeFalse
        [int]$raw['ThrottleLimit'] | Should -Be 5
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
        @{ Field = 'Targets'; Value = ('a' * 65537); Shown = 'over 65536 chars' }
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

    It 'accepts Targets of exactly 65536 chars' {
        (Resolve-Raw @{ Targets = ('a' * 65536) }).Values.Targets.Length | Should -Be 65536
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

    It 'keeps a network <Field> unchecked and uncounted, and still checks local paths' -ForEach @(
        @{ Field = 'XccdfPath'; Unc = '\\srv\share\x.xml'; Mapped = 'Q:\stig\x.xml' }
        @{ Field = 'ContentPath'; Unc = '\\srv\share\content'; Mapped = 'Q:\content' }
        @{ Field = 'ContentDestination'; Unc = '\\srv\share\cache'; Mapped = 'Q:\cache' }
        @{ Field = 'IntegrationPath'; Unc = '\\srv\share\plugins'; Mapped = 'Q:\plugins' }
        @{ Field = 'JsonPath'; Unc = '\\srv\share\out\r.json'; Mapped = 'Q:\out\r.json' }
    ) {
        # Q: is a mapped network drive; the share itself must never be touched at startup.
        Mock -ModuleName woscap Get-WoscapGuiDriveType { if ($Name -eq 'Q') { 'Network' } else { 'Fixed' } }
        # Default mock forwards local checks to the real cmdlet (Pester 6 has no implicit fall-through).
        Mock -ModuleName woscap Test-Path { & (Get-Command Test-Path -CommandType Cmdlet) -LiteralPath $LiteralPath -PathType $PathType }
        Mock -ModuleName woscap Test-Path { $false } -ParameterFilter { "$LiteralPath" -like '\\*' -or "$LiteralPath" -like 'Q:*' }
        foreach ($p in $Unc, $Mapped) {
            $r = Resolve-Raw @{ $Field = $p }
            $r.Values[$Field] | Should -Be $p
            $r.Cleared | Should -Be 0
        }
        Should -Invoke -ModuleName woscap Test-Path -Times 0 -Exactly -Scope It -ParameterFilter { "$LiteralPath" -like '\\*' -or "$LiteralPath" -like 'Q:*' }
        # A local missing path in the same field is still checked and counted.
        (Resolve-Raw @{ $Field = $(if ($Field -eq 'JsonPath') { Join-Path $script:Gone 'r.json' } else { $script:Gone }) }).Cleared | Should -Be 1
        # And a local existing path is kept, so the check really ran rather than failed.
        $local = switch ($Field) { 'XccdfPath' { $script:File } 'JsonPath' { Join-Path $script:Dir 'r.json' } default { $script:Dir } }
        $r = Resolve-Raw @{ $Field = $local }
        $r.Values[$Field] | Should -Be $local
        $r.Cleared | Should -Be 0
    }

    It 'keeps network profile entries unchecked while dropping a missing local one' {
        Mock -ModuleName woscap Get-WoscapGuiDriveType { if ($Name -eq 'Q') { 'Network' } else { 'Fixed' } }
        # Default mock forwards local checks to the real cmdlet (Pester 6 has no implicit fall-through).
        Mock -ModuleName woscap Test-Path { & (Get-Command Test-Path -CommandType Cmdlet) -LiteralPath $LiteralPath -PathType $PathType }
        Mock -ModuleName woscap Test-Path { $false } -ParameterFilter { "$LiteralPath" -like '\\*' -or "$LiteralPath" -like 'Q:*' }
        $r = Resolve-Raw @{ Profiles = @('\\srv\share\p.psd1', $script:Gone, 'Q:\p.psd1', $script:ProfA) }
        @($r.Values.Profiles) | Should -Be @('\\srv\share\p.psd1', 'Q:\p.psd1', $script:ProfA)
        $r.Cleared | Should -Be 1
        Should -Invoke -ModuleName woscap Test-Path -Times 0 -Exactly -Scope It -ParameterFilter { "$LiteralPath" -like '\\*' -or "$LiteralPath" -like 'Q:*' }
    }

    It 'checks a local drive normally' {
        InModuleScope woscap { Get-WoscapGuiDriveType -Name ($env:SystemDrive.Substring(0, 1)) } | Should -Not -Be 'Network'
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

# Runs last in this file, after every test that could have reached the settings path.
Describe 'Real %LOCALAPPDATA% guard' {
    It 'left the real GUI settings file untouched' {
        if (-not $script:RealSettings) { Set-ItResult -Skipped -Because 'LOCALAPPDATA is not set'; return }
        Get-RealSettingsStamp | Should -Be $script:RealBefore -Because "tests must mock Get-WoscapGuiSettingsPath, never write $($script:RealSettings)"
    }
}

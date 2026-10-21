BeforeDiscovery {
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms

    # Own inline schema; never read from the bundled manifests (they change under Task 1).
    $script:AllTypes = @(
        @{ Name = 'Server';     Type = 'Text';       Required = $true; Hooks = @('Export-Findings') }
        @{ Name = 'Port';       Type = 'Number';     Default = 10051;  Hooks = @('Export-Findings') }
        @{ Name = 'Insecure';   Type = 'Bool';       Hooks = @('Export-Findings') }
        @{ Name = 'Credential'; Type = 'Credential'; Hooks = @('Export-Findings') }
        @{ Name = 'Token';      Type = 'Secret';     Hooks = @('Export-Findings') }
        @{ Name = 'Targets';    Type = 'List';       Hooks = @('Export-Findings') }
        @{ Name = 'HostMap';    Type = 'Table';      Hooks = @('Export-Findings') }
        @{ Name = 'FactsPath';  Type = 'Path';       Hooks = @('Export-Findings'); Help = 'Where facts go.' }
    )
    $script:LongName = 'A_Really_Long_Option_Name_With_No_Spaces_That_Would_Push_The_Field_Column_Off_The_Form_' + ('X' * 40)

    function Assert-InsideParent([System.Windows.Forms.Control] $Root) {
        foreach ($c in $Root.Controls) {
            if ($c.Visible) {
                $c.Left  | Should -BeGreaterOrEqual 0 -Because "$($c.GetType().Name) '$($c.Text)'"
                $c.Right | Should -BeLessOrEqual $c.Parent.ClientSize.Width -Because "$($c.GetType().Name) '$($c.Text)' R=$($c.Right) W=$($c.Parent.ClientSize.Width)"
                $f = $c.FindForm()
                if ($c -is [System.Windows.Forms.Button] -and ($c -eq $f.CancelButton -or ($f.Tag -is [hashtable] -and $c -eq $f.Tag['Run']))) {
                    $r = $f.RectangleToClient($c.RectangleToScreen($c.ClientRectangle))
                    $r.Bottom | Should -BeLessOrEqual $f.ClientSize.Height -Because "button '$($c.Text)' B=$($r.Bottom) H=$($f.ClientSize.Height)"
                    $r.Right  | Should -BeLessOrEqual $f.ClientSize.Width -Because "button '$($c.Text)'"
                }
            }
            Assert-InsideParent $c
        }
    }
    function Test-Shown([System.Windows.Forms.Form] $Form, [switch] $Minimum) {
        try {
            $Form.Show()
            if ($Minimum) { $Form.Size = $Form.MinimumSize }
            [System.Windows.Forms.Application]::DoEvents()
            Assert-InsideParent $Form
        } finally { $Form.Close(); $Form.Dispose() }
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapGuiConfigOptions' {
    BeforeAll {
        $script:Root = Join-Path $TestDrive 'plugins'
        $withSchema = Join-Path $script:Root 'WithSchema'
        $noSchema = Join-Path $script:Root 'NoSchema'
        [void](New-Item -ItemType Directory -Path $withSchema, $noSchema -Force)
        Set-Content -LiteralPath (Join-Path $withSchema 'plugin.psd1') -Encoding ASCII -Value @'
@{
    Name = 'WithSchema'; Version = '1.0.0'; Capabilities = @('Get-Targets', 'Export-Findings')
    ConfigOptions = @(
        @{ Name = 'Zeta';  Type = 'Text';   Hooks = @('Export-Findings') }
        @{ Name = 'Alpha'; Type = 'Secret'; Hooks = @('Get-Targets', 'Export-Findings') }
        @{ Name = 'Only';  Type = 'List';   Hooks = @('Get-Targets') }
    )
}
'@
        Set-Content -LiteralPath (Join-Path $noSchema 'plugin.psd1') -Encoding ASCII -Value "@{ Name = 'NoSchema'; Capabilities = @('Get-Targets') }"
    }
    BeforeEach {
        Mock Show-WoscapGuiMessage { } -ModuleName woscap
        Mock Get-WoscapGuiCredential { } -ModuleName woscap
        Mock Get-WoscapGuiOpenPath { @() } -ModuleName woscap
    }
    It 'returns the entries for the hook in declared order' {
        InModuleScope woscap -Parameters @{ P = (Join-Path $script:Root 'WithSchema') } {
            param($P)
            $plugin = [pscustomobject]@{ Name = 'WithSchema'; Path = $P }
            $o = Get-WoscapGuiConfigOptions -Plugin $plugin -Hook 'Export-Findings'
            @($o | ForEach-Object { $_.Name }) | Should -Be @('Zeta', 'Alpha')
            $one = Get-WoscapGuiConfigOptions -Plugin $plugin -Hook 'Get-Targets'
            @($one | ForEach-Object { $_.Name }) | Should -Be @('Alpha', 'Only')
        }
    }
    It 'returns an empty list (not $null) when the schema has nothing for the hook' {
        InModuleScope woscap -Parameters @{ P = (Join-Path $script:Root 'WithSchema') } {
            param($P)
            $o = Get-WoscapGuiConfigOptions -Plugin ([pscustomobject]@{ Path = $P }) -Hook 'New-Remediation'
            $null -eq $o | Should -BeFalse
            @($o).Count | Should -Be 0
        }
    }
    It 'returns $null when the plugin declares no schema' {
        InModuleScope woscap -Parameters @{ P = (Join-Path $script:Root 'NoSchema') } {
            param($P)
            $o = Get-WoscapGuiConfigOptions -Plugin ([pscustomobject]@{ Path = $P }) -Hook 'Get-Targets'
            $null -eq $o | Should -BeTrue
        }
    }
    It 'prefers ConfigOptions carried on the plugin object' {
        InModuleScope woscap -Parameters @{ P = (Join-Path $script:Root 'NoSchema') } {
            param($P)
            $plugin = [pscustomobject]@{ Path = $P; ConfigOptions = @(@{ Name = 'X'; Type = 'Text'; Hooks = @('Get-Targets') }) }
            @(Get-WoscapGuiConfigOptions -Plugin $plugin -Hook 'Get-Targets' | ForEach-Object { $_.Name }) | Should -Be @('X')
        }
    }
}

Describe 'Config form values' -Skip:(-not $script:IsSta) {
    BeforeEach {
        Mock Show-WoscapGuiMessage { } -ModuleName woscap
        Mock Get-WoscapGuiCredential { } -ModuleName woscap
        Mock Get-WoscapGuiOpenPath { @() } -ModuleName woscap
    }
    It 'maps every type to its exact .NET type and value' {
        InModuleScope woscap -Parameters @{ Options = $script:AllTypes } {
            param($Options)
            $pw = ConvertTo-SecureString 'S3cretPw!' -AsPlainText -Force
            $script:TestCred = New-Object System.Management.Automation.PSCredential('svc-user', $pw)
            Mock Get-WoscapGuiCredential { $script:TestCred }
            $d = New-WoscapGuiConfigForm -Options $Options -Title 'Export findings'
            try {
                $d.Show(); [System.Windows.Forms.Application]::DoEvents()
                $fl = $d.Tag['Fields']
                $fl['Server'].Control.Text = '  zbx.example.test  '
                $fl['Port'].Control.Text = '10052'
                $fl['Insecure'].Control.Checked = $true
                $fl['Credential'].Control.PerformClick()
                $fl['Token'].Control.Text = 'tok en'
                $fl['Targets'].Control.Text = "host1`r`n`r`n  host2  `r`n   `r`n"
                [void]$fl['HostMap'].Control.Rows.Add('10.0.0.1', 'web01')
                [void]$fl['HostMap'].Control.Rows.Add('10.0.0.2', 'web02')
                $fl['FactsPath'].Control.Text = 'C:\facts.json'
                $c = Get-WoscapGuiConfigValue -Form $d
                $c | Should -BeOfType [hashtable]
                $c['Server'] | Should -BeOfType [string]; $c['Server'] | Should -BeExactly 'zbx.example.test'
                $c['Port'] | Should -BeOfType [int]; $c['Port'] | Should -Be 10052
                $c['Insecure'] | Should -BeOfType [bool]; $c['Insecure'] | Should -BeTrue
                $c['Credential'] | Should -BeOfType [pscredential]; $c['Credential'].UserName | Should -BeExactly 'svc-user'
                $c['Token'] | Should -BeOfType [string]; $c['Token'] | Should -BeExactly 'tok en'
                , $c['Targets'] | Should -BeOfType [string[]]; $c['Targets'] | Should -Be @('host1', 'host2')
                $c['HostMap'] | Should -BeOfType [hashtable]
                $c['HostMap']['10.0.0.1'] | Should -BeExactly 'web01'; $c['HostMap'].Count | Should -Be 2
                $c['FactsPath'] | Should -BeOfType [string]; $c['FactsPath'] | Should -BeExactly 'C:\facts.json'
                Should -Invoke Get-WoscapGuiCredential -Times 1 -Exactly
            } finally { $d.Close(); $d.Dispose() }
        }
    }
    It 'keeps a one-item List a string[]' {
        InModuleScope woscap {
            $d = New-WoscapGuiConfigForm -Options @(@{ Name = 'L'; Type = 'List'; Hooks = @('Get-Targets') }) -Title 't'
            try {
                $d.Tag['Fields']['L'].Control.Text = 'only'
                $c = Get-WoscapGuiConfigValue -Form $d
                , $c['L'] | Should -BeOfType [string[]]
                $c['L'].Count | Should -Be 1
            } finally { $d.Dispose() }
        }
    }
    It 'omits optional fields left empty (Bool is always a value)' {
        InModuleScope woscap -Parameters @{ Options = $script:AllTypes } {
            param($Options)
            $opts = @($Options | ForEach-Object { $h = $_.Clone(); $h.Remove('Default'); $h.Remove('Required'); $h })
            $d = New-WoscapGuiConfigForm -Options $opts -Title 't'
            try {
                $c = Get-WoscapGuiConfigValue -Form $d
                @($c.Keys) | Should -Be @('Insecure')
                $c['Insecure'] | Should -BeFalse
            } finally { $d.Dispose() }
        }
    }
    It 'prefills Defaults and returns them typed' {
        InModuleScope woscap {
            $opts = @(
                @{ Name = 'T'; Type = 'Text';   Default = 'abc';                  Hooks = @('h') }
                @{ Name = 'N'; Type = 'Number'; Default = 42;                     Hooks = @('h') }
                @{ Name = 'B'; Type = 'Bool';   Default = $true;                  Hooks = @('h') }
                @{ Name = 'L'; Type = 'List';   Default = @('a', 'b');            Hooks = @('h') }
                @{ Name = 'M'; Type = 'Table';  Default = @{ k1 = 'v1'; k2 = 'v2' }; Hooks = @('h') }
                @{ Name = 'P'; Type = 'Path';   Default = 'C:\x';                 Hooks = @('h') }
            )
            $d = New-WoscapGuiConfigForm -Options $opts -Title 't'
            try {
                $fl = $d.Tag['Fields']
                $fl['T'].Control.Text | Should -BeExactly 'abc'
                $fl['N'].Control.Text | Should -BeExactly '42'
                $fl['B'].Control.Checked | Should -BeTrue
                $c = Get-WoscapGuiConfigValue -Form $d
                $c['T'] | Should -BeExactly 'abc'
                $c['N'] | Should -BeOfType [int]; $c['N'] | Should -Be 42
                $c['B'] | Should -BeTrue
                $c['L'] | Should -Be @('a', 'b')
                $c['M']['k2'] | Should -BeExactly 'v2'
                $c['P'] | Should -BeExactly 'C:\x'
            } finally { $d.Dispose() }
        }
    }
    It 'reports missing Required fields of every type (<Type>)' -ForEach @(
        @{ Type = 'Text' }, @{ Type = 'Number' }, @{ Type = 'Credential' }, @{ Type = 'Secret' },
        @{ Type = 'List' }, @{ Type = 'Table' }, @{ Type = 'Path' }
    ) {
        InModuleScope woscap -Parameters @{ Type = $Type } {
            param($Type)
            $d = New-WoscapGuiConfigForm -Options @(@{ Name = 'Need'; Type = $Type; Required = $true; Hooks = @('h') }) -Title 't'
            try {
                $r = Read-WoscapGuiConfigForm -Form $d
                @($r.Errors).Count | Should -Be 1
                $r.Errors[0] | Should -Match 'Need'
                { Get-WoscapGuiConfigValue -Form $d } | Should -Throw '*Need*'
            } finally { $d.Dispose() }
        }
    }
    It 'keeps the form open with a message when Required is missing (Run click)' {
        InModuleScope woscap {
            $d = New-WoscapGuiConfigForm -Options @(@{ Name = 'Server'; Type = 'Text'; Required = $true; Hooks = @('h') }) -Title 't'
            try {
                $d.Show(); [System.Windows.Forms.Application]::DoEvents()
                $d.Tag['Run'].PerformClick()
                Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly -ParameterFilter { $Text -match 'Server' }
                $d.DialogResult | Should -Not -Be ([System.Windows.Forms.DialogResult]::OK)
                $d.Visible | Should -BeTrue
                $d.Tag['Fields']['Server'].Control.Text = 'x'
                $d.Tag['Run'].PerformClick()
                $d.DialogResult | Should -Be ([System.Windows.Forms.DialogResult]::OK)
                Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly
            } finally { $d.Close(); $d.Dispose() }
        }
    }
    It 'keeps a Number inside the int range' {
        InModuleScope woscap {
            $d = New-WoscapGuiConfigForm -Options @(@{ Name = 'Port'; Type = 'Number'; Hooks = @('h') }) -Title 't'
            try {
                $d.Tag['Fields']['Port'].Control.Text = '99999999999'
                $c = Get-WoscapGuiConfigValue -Form $d
                $c['Port'] | Should -BeOfType [int]; $c['Port'] | Should -Be ([int]::MaxValue)
            } finally { $d.Dispose() }
        }
    }
    It 'rejects duplicate Table keys and a value without a key; ignores blank rows' {
        InModuleScope woscap {
            $d = New-WoscapGuiConfigForm -Options @(@{ Name = 'Map'; Type = 'Table'; Hooks = @('h') }) -Title 't'
            try {
                $g = $d.Tag['Fields']['Map'].Control
                [void]$g.Rows.Add('a', '1'); [void]$g.Rows.Add(' A ', '2'); [void]$g.Rows.Add('', '')
                $e = @((Read-WoscapGuiConfigForm -Form $d).Errors)
                $e.Count | Should -Be 1; $e[0] | Should -Match 'duplicate'
                $g.Rows.Clear(); [void]$g.Rows.Add('', 'orphan')
                @((Read-WoscapGuiConfigForm -Form $d).Errors)[0] | Should -Match 'key'
                $g.Rows.Clear(); [void]$g.Rows.Add(' a ', ' 1 '); [void]$g.Rows.Add('', '')
                $c = Get-WoscapGuiConfigValue -Form $d
                $c['Map']['a'] | Should -BeExactly '1'; $c['Map'].Count | Should -Be 1
            } finally { $d.Dispose() }
        }
    }
    It 'masks Secret fields' {
        InModuleScope woscap {
            $d = New-WoscapGuiConfigForm -Options @(@{ Name = 'Token'; Type = 'Secret'; Hooks = @('h') }) -Title 't'
            try { $d.Tag['Fields']['Token'].Control.UseSystemPasswordChar | Should -BeTrue } finally { $d.Dispose() }
        }
    }
    It 'never shows the credential or secret in any label or text' {
        InModuleScope woscap {
            $pw = ConvertTo-SecureString 'S3cretPw!' -AsPlainText -Force
            $script:TestCred = New-Object System.Management.Automation.PSCredential('svc-user', $pw)
            Mock Get-WoscapGuiCredential { $script:TestCred }
            $opts = @(
                @{ Name = 'Credential'; Type = 'Credential'; Hooks = @('h') }
                @{ Name = 'Token'; Type = 'Secret'; Hooks = @('h') }
            )
            $d = New-WoscapGuiConfigForm -Options $opts -Title 't'
            try {
                $d.Show(); [System.Windows.Forms.Application]::DoEvents()
                $fl = $d.Tag['Fields']
                $fl['Credential'].Status.Text | Should -BeExactly '(not set)'
                $fl['Credential'].Control.PerformClick()
                $fl['Token'].Control.Text = 'TopSecretToken'
                $fl['Credential'].Status.Text | Should -BeExactly '(set)'
                $walk = { param($r) foreach ($x in $r.Controls) { $x; & $walk $x } }
                foreach ($c in @(& $walk $d)) {
                    if ($c -eq $fl['Token'].Control) { continue }
                    [string]$c.Text | Should -Not -Match 'S3cretPw|svc-user|TopSecretToken' -Because $c.GetType().Name
                }
                [string]$d.Text | Should -Not -Match 'S3cretPw|svc-user|TopSecretToken'
            } finally { $d.Close(); $d.Dispose() }
        }
    }
    It 'keeps the previous credential when the credential prompt is cancelled' {
        InModuleScope woscap {
            $d = New-WoscapGuiConfigForm -Options @(@{ Name = 'Cred'; Type = 'Credential'; Hooks = @('h') }) -Title 't'
            try {
                $d.Show(); [System.Windows.Forms.Application]::DoEvents()
                $d.Tag['Fields']['Cred'].Control.PerformClick()
                Should -Invoke Get-WoscapGuiCredential -Times 1 -Exactly
                $d.Tag['Fields']['Cred'].Status.Text | Should -BeExactly '(not set)'
                (Get-WoscapGuiConfigValue -Form $d).ContainsKey('Cred') | Should -BeFalse
            } finally { $d.Close(); $d.Dispose() }
        }
    }
    It 'Browse fills a Path field through the open-path seam' {
        InModuleScope woscap {
            Mock Get-WoscapGuiOpenPath { @('C:\picked\file.json') }
            $d = New-WoscapGuiConfigForm -Options @(@{ Name = 'P'; Type = 'Path'; Hooks = @('h') }) -Title 't'
            try {
                $d.Show(); [System.Windows.Forms.Application]::DoEvents()
                $d.Tag['Fields']['P'].Browse.PerformClick()
                $d.Tag['Fields']['P'].Control.Text | Should -BeExactly 'C:\picked\file.json'
            } finally { $d.Close(); $d.Dispose() }
        }
    }
    It 'never makes Run the accept button; Cancel is the cancel button' {
        InModuleScope woscap {
            $d = New-WoscapGuiConfigForm -Options @(@{ Name = 'X'; Type = 'Text'; Hooks = @('h') }) -Title 't'
            try {
                $d.AcceptButton | Should -BeNullOrEmpty
                $d.CancelButton | Should -Be $d.Tag['Cancel']
                $d.Tag['Run'].DialogResult | Should -Be ([System.Windows.Forms.DialogResult]::None)
            } finally { $d.Dispose() }
        }
    }
}

Describe 'Generic config grid' -Skip:(-not $script:IsSta) {
    BeforeEach {
        Mock Show-WoscapGuiMessage { } -ModuleName woscap
        Mock Get-WoscapGuiCredential { } -ModuleName woscap
        Mock Get-WoscapGuiOpenPath { @() } -ModuleName woscap
    }
    It 'is used when Options is $null and builds the same types' {
        InModuleScope woscap {
            $d = New-WoscapGuiConfigForm -Options $null -Title 't'
            try {
                $d.Tag['Mode'] | Should -BeExactly 'Generic'
                $g = $d.Tag['Grid']
                [void]$g.Rows.Add(' Server ', 'Text', ' zbx ')
                [void]$g.Rows.Add('Port', 'Number', '10051')
                [void]$g.Rows.Add('Insecure', 'Bool', 'true')
                [void]$g.Rows.Add('Targets', 'List', 'a, b,,c')
                [void]$g.Rows.Add('Out', 'Path', 'C:\o')
                [void]$g.Rows.Add('', '', '')
                [void]$g.Rows.Add('Empty', 'Text', '')
                $c = Get-WoscapGuiConfigValue -Form $d
                @($c.Keys | Sort-Object) | Should -Be @('Insecure', 'Out', 'Port', 'Server', 'Targets')
                $c['Server'] | Should -BeExactly 'zbx'
                $c['Port'] | Should -BeOfType [int]; $c['Port'] | Should -Be 10051
                $c['Insecure'] | Should -BeOfType [bool]; $c['Insecure'] | Should -BeTrue
                , $c['Targets'] | Should -BeOfType [string[]]; $c['Targets'] | Should -Be @('a', 'b', 'c')
                $c['Out'] | Should -BeExactly 'C:\o'
            } finally { $d.Dispose() }
        }
    }
    It 'treats a blank type as Text' {
        InModuleScope woscap {
            $d = New-WoscapGuiConfigForm -Options $null -Title 't'
            try {
                [void]$d.Tag['Grid'].Rows.Add('K', $null, 'v')
                (Get-WoscapGuiConfigValue -Form $d)['K'] | Should -BeExactly 'v'
            } finally { $d.Dispose() }
        }
    }
    It 'rejects bad values and duplicate keys (<Case>)' -ForEach @(
        @{ Case = 'number'; Rows = @(, @('P', 'Number', 'x')) }
        @{ Case = 'bool';   Rows = @(, @('B', 'Bool', 'maybe')) }
        @{ Case = 'dup';    Rows = @(@('K', 'Text', '1'), @('k', 'Text', '2')) }
        @{ Case = 'nokey';  Rows = @(, @('', 'Text', 'v')) }
    ) {
        InModuleScope woscap -Parameters @{ Rows = $Rows } {
            param($Rows)
            $d = New-WoscapGuiConfigForm -Options $null -Title 't'
            try {
                foreach ($r in $Rows) { [void]$d.Tag['Grid'].Rows.Add([object[]]$r) }
                @((Read-WoscapGuiConfigForm -Form $d).Errors).Count | Should -Be 1
            } finally { $d.Dispose() }
        }
    }
    It 'offers no Credential, Secret or Table type (they cannot be entered safely in a cell)' {
        InModuleScope woscap {
            $d = New-WoscapGuiConfigForm -Options $null -Title 't'
            try {
                $items = @($d.Tag['Grid'].Columns['Type'].Items)
                $items | Should -Not -Contain 'Credential'
                $items | Should -Not -Contain 'Secret'
                $items | Should -Not -Contain 'Table'
            } finally { $d.Dispose() }
        }
    }
    It 'shows an empty schema (no options for the hook) as a form with only Run and Cancel' {
        InModuleScope woscap {
            $d = New-WoscapGuiConfigForm -Options @() -Title 't'
            try {
                $d.Tag['Mode'] | Should -BeExactly 'Schema'
                $c = Get-WoscapGuiConfigValue -Form $d
                $c.Count | Should -Be 0
            } finally { $d.Dispose() }
        }
    }
}

Describe 'Show-WoscapGuiConfigForm' {
    It 'returns $null on cancel and the typed hashtable on OK (fake form, never modal)' -ForEach @(
        @{ Result = 'Cancel'; Expect = $null }
        @{ Result = 'OK'; Expect = 'v' }
    ) {
        InModuleScope woscap -Parameters @{ Result = $Result; Expect = $Expect } {
            param($Result, $Expect)
            Mock Show-WoscapGuiMessage { }
            Mock Get-WoscapGuiCredential { }
            $script:FakeResult = [System.Windows.Forms.DialogResult]$Result
            Mock New-WoscapGuiConfigForm {
                $f = [pscustomobject]@{ Tag = @{}; Disposed = $false }
                $f | Add-Member -MemberType ScriptMethod -Name ShowDialog -Value { $script:FakeResult }
                $f | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $this.Disposed = $true }
                $script:Fake = $f
                $f
            }
            Mock Get-WoscapGuiConfigValue { @{ K = 'v' } }
            $r = Show-WoscapGuiConfigForm -Options @(@{ Name = 'K'; Type = 'Text'; Hooks = @('h') }) -Title 't'
            if ($null -eq $Expect) { $r | Should -BeNullOrEmpty } else { $r['K'] | Should -BeExactly $Expect }
            $script:Fake.Disposed | Should -BeTrue
        }
    }
}

Describe 'Config form layout' -Skip:(-not $script:IsSta) {
    BeforeEach {
        Mock Show-WoscapGuiMessage { } -ModuleName woscap
        Mock Get-WoscapGuiCredential { } -ModuleName woscap
        Mock Get-WoscapGuiOpenPath { @() } -ModuleName woscap
    }
    It 'keeps every control inside its parent (<Case>, minimum=<Min>)' -ForEach @(
        @{ Case = 'every type'; Min = $false; Kind = 'all' }
        @{ Case = 'every type'; Min = $true;  Kind = 'all' }
        @{ Case = '15 options, long names'; Min = $false; Kind = 'many' }
        @{ Case = '15 options, long names'; Min = $true;  Kind = 'many' }
        @{ Case = 'generic grid'; Min = $false; Kind = 'generic' }
        @{ Case = 'generic grid'; Min = $true;  Kind = 'generic' }
    ) {
        $types = 'Text', 'Number', 'Bool', 'Credential', 'Secret', 'List', 'Table', 'Path'
        $opts = switch ($Kind) {
            'all' { , $script:AllTypes }
            'many' { , @(for ($i = 0; $i -lt 15; $i++) { @{ Name = "$($script:LongName)$i"; Type = $types[$i % 8]; Required = ($i % 2 -eq 0); Hooks = @('h'); Help = ('help ' * 50) } }) }
            'generic' { , $null }
        }
        $d = InModuleScope woscap -Parameters @{ O = $opts } { param($O) New-WoscapGuiConfigForm -Options $O -Title ('Configure ' + ('Plugin' * 20)) }
        if ($Kind -eq 'many') {
            foreach ($f in $d.Tag['Fields'].Values) {
                if ($f.Control -is [System.Windows.Forms.TextBox]) { $f.Control.Text = ('long-value-' * 30) }
            }
        }
        Test-Shown $d -Minimum:$Min
    }
}

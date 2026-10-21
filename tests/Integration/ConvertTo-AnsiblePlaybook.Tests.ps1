BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Expected = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/ansible/expected-playbook.yml'

    # Returns the literal-block 'script: |' body of the first audit task, de-indented.
    function Get-EmbeddedAuditScript([string] $Yaml) {
        $lines = $Yaml -split "\r?\n"
        $start = -1
        for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -eq '        script: |') { $start = $i + 1; break } }
        if ($start -lt 0) { throw 'no script block in YAML' }
        $body = [System.Collections.Generic.List[string]]::new()
        for ($i = $start; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -eq '') { $body.Add(''); continue }
            if (-not $lines[$i].StartsWith('          ')) { break }
            $body.Add($lines[$i].Substring(10))
        }
        ($body -join "`n").TrimEnd()
    }

    function New-AuditPlaybook([string] $Subcategory, [string[]] $Expected) {
        InModuleScope woscap -Parameters @{ Sub = $Subcategory; Exp = $Expected } {
            $i = 0
            $failed = @(); $pack = @{}
            foreach ($e in $Exp) {
                $i++
                $id = "WN11-AU-00090$i"
                $failed += [pscustomobject]@{ StigId = $id; Title = "Rule $i"; Status = 'Open' }
                $pack[$id] = @{ Type = 'AuditPolicy'; Subcategory = $Sub; Operator = 'includes'; Expected = $e }
            }
            ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack
        }
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'ConvertTo-AnsiblePlaybook' {
    It 'emits win_regedit and enable-only win_powershell audit tasks and a manual comment' {
        InModuleScope woscap -Parameters @{ Expected = $script:Expected } {
            $failed = @(
                [pscustomobject]@{ StigId = 'WN11-00-000032'; Title = 'MinimumPIN'; Status = 'Open' },
                [pscustomobject]@{ StigId = 'WN11-AU-000010'; Title = 'Credential Validation'; Status = 'Open' },
                [pscustomobject]@{ StigId = 'WN11-99-000001'; Title = 'Some manual-only rule'; Status = 'Open' }
            )
            $pack = @{
                'WN11-00-000032' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'; Name = 'MinimumPIN'; Operator = 'ge'; Expected = 6 }
                'WN11-AU-000010' = @{ Type = 'AuditPolicy'; Subcategory = 'Credential Validation'; Operator = 'includes'; Expected = 'Success' }
                'WN11-99-000001' = @{ Type = 'Script'; Script = { 'Fail' } }
            }
            $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack
            $expected = (Get-Content -LiteralPath $Expected -Raw) -replace "`r`n", "`n"
            ($text -replace "`r`n", "`n").TrimEnd() | Should -Be $expected.TrimEnd()
        }
    }
    It 'never emits a task for a passing rule' {
        InModuleScope woscap {
            $failed = @()   # caller passes only Open rules
            $pack = @{ 'X' = @{ Type = 'Registry'; Path = 'p'; Name = 'n'; Expected = 1 } }
            (ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack) | Should -Match 'hosts: all'
        }
    }
    It 'emits a # manual line (no throw, no task) for a Registry descriptor missing Expected' {
        InModuleScope woscap {
            $failed = @([pscustomobject]@{ StigId = 'WN11-XX-000001'; Title = 'Partial reg'; Status = 'Open' })
            $pack = @{ 'WN11-XX-000001' = @{ Type = 'Registry'; Path = 'p'; Name = 'n' } }  # no Expected
            $text = $null
            { $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack } | Should -Not -Throw
            $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack
            $text | Should -Match '# manual: WN11-XX-000001'
            $text | Should -Not -Match 'win_regedit'
        }
    }
    It 'emits a # manual line with the reason, not a win_regedit task, for a rule opted out with Remediate = $false' {
        InModuleScope woscap {
            $failed = @([pscustomobject]@{ StigId = 'WNDF-AV-000011'; Title = 'Safe samples'; Status = 'Open' })
            $pack = @{ 'WNDF-AV-000011' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'; Name = 'SubmitSamplesConsent'
                                             Operator = 'eq'; Expected = 1; Remediate = $false; RemediateReason = 'NA on classified systems' } }
            $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack
            $text | Should -Match '# manual: WNDF-AV-000011 .*NA on classified systems'
            $text | Should -Not -Match 'win_regedit'
        }
    }
    It 'emits a # manual line, not a win_regedit task, for a Registry rule whose operator has no safe write' {
        InModuleScope woscap {
            $failed = @([pscustomobject]@{ StigId = 'WN11-CC-000055'; Title = 'Multiple connections'; Status = 'Open' })
            $pack = @{ 'WN11-CC-000055' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'; Name = 'fMinimizeConnections'; Operator = 'ne'; Expected = 0 } }
            $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack
            $text | Should -Match "# manual: WN11-CC-000055 - Multiple connections \(.*operator 'ne'"
            $text | Should -Not -Match 'win_regedit'
        }
    }
    It 'merges paired Success+Failure rules for one subcategory into a single task' {
        InModuleScope woscap {
            $failed = @(
                [pscustomobject]@{ StigId = 'WN11-AU-000100'; Title = 'Logon Success'; Status = 'Open' },
                [pscustomobject]@{ StigId = 'WN11-AU-000101'; Title = 'Logon Failure'; Status = 'Open' }
            )
            $pack = @{
                'WN11-AU-000100' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Operator = 'includes'; Expected = 'Success' }
                'WN11-AU-000101' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Operator = 'includes'; Expected = 'Failure' }
            }
            $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack
            @($text -split "`n" | Where-Object { $_ -match 'ansible\.windows\.win_powershell:' }).Count | Should -Be 1
            # The name carries a colon, so it MUST be quoted or the YAML is invalid.
            $text | Should -Match 'name: "Audit policy: Logon"'
            # Both directions travel as separate list items, never one 'success and failure' string.
            $text | Should -Match '(?m)^          Directions:\r?\n            - success\r?\n            - failure\r?$'
            $text | Should -Not -Match 'success and failure'
        }
    }
    It 'quotes an audit task name so the colon does not break YAML parsing' {
        InModuleScope woscap {
            $failed = @([pscustomobject]@{ StigId = 'WN11-AU-000010'; Title = 'Credential Validation'; Status = 'Open' })
            $pack = @{ 'WN11-AU-000010' = @{ Type = 'AuditPolicy'; Subcategory = 'Credential Validation'; Operator = 'includes'; Expected = 'Success' } }
            $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack
            $nameLine = @($text -split "`n" | Where-Object { $_ -match '^\s*- name:' })[-1]
            # An unquoted "Audit policy: <sub>" would embed a bare ': ' (YAML mapping
            # indicator). Require the value to be double-quoted.
            $nameLine | Should -Match ':\s*"[^"]*"\s*$'
        }
    }
    It 'emits a # manual line (no throw) when a descriptor is a bare scriptblock, not a hashtable' {
        InModuleScope woscap {
            $failed = @([pscustomobject]@{ StigId = 'WN11-XX-000002'; Title = 'Override rule'; Status = 'Open' })
            $pack = @{ 'WN11-XX-000002' = { 'Fail' } }  # bare scriptblock, no ContainsKey
            $text = $null
            { $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack } | Should -Not -Throw
            $text = ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack
            $text | Should -Match '# manual: WN11-XX-000002'
        }
    }
    It 'never emits a disable flag or win_audit_policy_system (<Label>)' -TestCases @(
        @{ Label = 'success only'; Exp = @('Success') }
        @{ Label = 'failure only'; Exp = @('Failure') }
        @{ Label = 'both';         Exp = @('Success', 'Failure') }
    ) {
        $text = New-AuditPlaybook -Subcategory 'Logon' -Expected $Exp
        $text | Should -Not -Match 'disable'
        $text | Should -Not -Match 'win_audit_policy_system'
        @($text -split "`n" | Where-Object { $_ -match '^    - name:' }).Count | Should -Be 1
    }
    It 'emits exactly the required directions as parameters (<Label>)' -TestCases @(
        @{ Label = 'success only'; Exp = @('Success'); Want = @('success') }
        @{ Label = 'failure only'; Exp = @('Failure'); Want = @('failure') }
        @{ Label = 'both';         Exp = @('Failure', 'Success'); Want = @('success', 'failure') }
    ) {
        $text = New-AuditPlaybook -Subcategory 'Logon' -Expected $Exp
        $got = @($text -split "\r?\n" | Where-Object { $_ -match '^            - (\S+)$' } | ForEach-Object { $_.Trim().Substring(2) })
        $got | Should -Be $Want
    }
    It 'keeps a subcategory with quotes and a colon a quoted parameter value, never script text' {
        $sub = 'It''s "odd": a\b # x'
        $text = New-AuditPlaybook -Subcategory $sub -Expected @('Success')
        $lines = $text -split "\r?\n"
        $lines | Should -Contain '    - name: "Audit policy: It''s \"odd\": a\\b # x"'
        $lines | Should -Contain '          Subcategory: "It''s \"odd\": a\\b # x"'
        # The subcategory appears on exactly those two lines and nowhere in the script.
        @($lines | Where-Object { $_.Contains('odd') }).Count | Should -Be 2
        Get-EmbeddedAuditScript $text | Should -Not -Match 'odd'
    }
    It 'embeds the canonical enable-only script verbatim' {
        $text = New-AuditPlaybook -Subcategory 'Logon' -Expected @('Success', 'Failure')
        $canonical = InModuleScope woscap { Get-WoscapAnsibleAuditScript }
        Get-EmbeddedAuditScript $text | Should -Be (($canonical -replace "\r\n", "`n").TrimEnd())
    }
    It 'declares SupportsShouldProcess so win_powershell runs the script under --check' {
        $text = New-AuditPlaybook -Subcategory 'Logon' -Expected @('Success')
        $ast = [scriptblock]::Create((Get-EmbeddedAuditScript $text)).Ast
        $binding = @($ast.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' })
        $binding.Count | Should -Be 1
        @($binding[0].NamedArguments | Where-Object { $_.ArgumentName -eq 'SupportsShouldProcess' }).Count | Should -Be 1
    }
    It 'quotes every registry scalar so YAML neither re-types nor misparses it' {
        $text = InModuleScope woscap {
            $failed = @(
                [pscustomobject]@{ StigId = 'R-1'; Title = '*star: x'; Status = 'Open' },
                [pscustomobject]@{ StigId = 'R-2'; Title = 'yes'; Status = 'Open' }
            )
            $pack = @{
                'R-1' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\#x'; Name = '"Administrator"'; Operator = 'eq'; Expected = '10'; Kind = 'string' }
                'R-2' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\: x'; Name = '#x'; Operator = 'eq'; Expected = 'yes' }
            }
            ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack $pack
        }
        $lines = $text -split "\r?\n"
        $lines | Should -Contain '    - name: "R-1 - *star: x"'
        $lines | Should -Contain '        path: "HKLM:\\SOFTWARE\\#x"'
        $lines | Should -Contain '        name: "\"Administrator\""'
        $lines | Should -Contain '        data: "10"'
        $lines | Should -Contain '        type: "string"'
        $lines | Should -Contain '    - name: "R-2 - yes"'
        $lines | Should -Contain '        path: "HKLM:\\SOFTWARE\\: x"'
        $lines | Should -Contain '        name: "#x"'
        $lines | Should -Contain '        data: "yes"'
    }
    It 'keeps a # manual line on one line when the title holds a line break (<Label>)' -TestCases @(
        @{ Label = 'LF';   Break = "`n" }
        @{ Label = 'CRLF'; Break = "`r`n" }
        @{ Label = 'NEL';  Break = [string][char]0x85 }
        @{ Label = 'LS';   Break = [string][char]0x2028 }
        @{ Label = 'PS';   Break = [string][char]0x2029 }
    ) {
        $text = InModuleScope woscap -Parameters @{ Break = $Break } {
            $failed = @([pscustomobject]@{ StigId = 'M-1'; Title = "first$($Break)- name: injected"; Status = 'Open' })
            ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack @{ 'M-1' = @{ Type = 'Script'; Script = { 'Fail' } } }
        }
        # AppendLine ends lines with CRLF on Windows; only a break inside the title is a failure.
        ($text -replace "`r`n", "`n") | Should -Not -Match '[\r\x85\p{Zl}\p{Zp}]'
        $hit = @($text -split "`n" | Where-Object { $_ -match 'injected' })
        $hit.Count | Should -Be 1
        $hit[0] | Should -Match '^    # manual: M-1 - first - name: injected'
    }
    It 'emits the planner reason for an AuditPolicy rule with an unusable Expected' {
        $text = InModuleScope woscap {
            $failed = @([pscustomobject]@{ StigId = 'A-9'; Title = 'Bad audit'; Status = 'Open' })
            ConvertTo-AnsiblePlaybook -FailedRule $failed -ContentPack @{ 'A-9' = @{ Type = 'AuditPolicy'; Subcategory = 'Logon'; Expected = 'Bogus' } }
        }
        $text | Should -Not -Match 'win_powershell'
        $text | Should -Match "# manual: A-9 - Bad audit \(.*'Bogus'.*\)"
    }
}

Describe 'ConvertTo-WoscapYamlString' {
    It 'escapes <Label> so the output stays ASCII and one line' -TestCases @(
        @{ Label = 'C1 U+0080'; Char = 0x80;   Esc = '\x80' }
        @{ Label = 'NEL U+0085'; Char = 0x85;  Esc = '\x85' }
        @{ Label = 'C1 U+009F'; Char = 0x9F;   Esc = '\x9F' }
        @{ Label = 'LS U+2028'; Char = 0x2028; Esc = '\u2028' }
        @{ Label = 'PS U+2029'; Char = 0x2029; Esc = '\u2029' }
        @{ Label = 'LF';        Char = 0x0A;   Esc = '\x0A' }
        @{ Label = 'DEL';       Char = 0x7F;   Esc = '\x7F' }
    ) {
        $out = InModuleScope woscap -Parameters @{ C = [string][char]$Char } { ConvertTo-WoscapYamlString "a$($C)b" }
        $out | Should -BeExactly ('"a' + $Esc + 'b"')
    }
}

Describe 'Embedded Ansible audit script (auditpol mocked)' {
    BeforeAll {
        $script:AuditScript = Get-EmbeddedAuditScript (New-AuditPlaybook -Subcategory 'Logon' -Expected @('Success'))

        # Runs the emitted script with a fake $Ansible and a local 'auditpol' function
        # shadowing the real exe, so no real auditpol call is ever made.
        function Invoke-AuditScript {
            param([string] $Setting, [string[]] $Directions, [switch] $CheckMode, [int] $GetExit = 0, [int] $SetExit = 0, [string] $GetStderr)
            $script:AuditCalls = [System.Collections.Generic.List[object]]::new()
            $Ansible = [pscustomobject]@{ Changed = $null; CheckMode = [bool]$CheckMode }
            function auditpol {
                $script:AuditCalls.Add(@($args))
                if ($args[0] -eq '/get') {
                    $global:LASTEXITCODE = $GetExit
                    # Stands in for native stderr: arrives as an ErrorRecord under 2>&1.
                    if ($GetStderr) { Write-Error -Message $GetStderr -ErrorAction Continue }
                    ''
                    'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting'
                    "HOST,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},$Setting,"
                } else {
                    $global:LASTEXITCODE = $SetExit
                }
            }
            & ([scriptblock]::Create($script:AuditScript)) -Subcategory 'Logon' -Directions $Directions
            $Ansible
        }
        # Each /set call as one space-joined string, so assertions compare whole argument lists.
        function Get-SetCall { @($script:AuditCalls | Where-Object { $_[0] -eq '/set' } | ForEach-Object { $_ -join ' ' }) }
    }
    AfterAll { $global:LASTEXITCODE = 0 }

    It 'enables only the missing direction and reports Changed' {
        $a = Invoke-AuditScript -Setting 'Success' -Directions 'success', 'failure'
        $a.Changed | Should -BeTrue
        $set = @(Get-SetCall)
        $set.Count | Should -Be 1
        $set[0] | Should -BeExactly '/set /subcategory:Logon /failure:enable'
    }
    It 'enables both directions when nothing is audited' {
        $a = Invoke-AuditScript -Setting 'No Auditing' -Directions 'success', 'failure'
        $a.Changed | Should -BeTrue
        @(Get-SetCall) | Should -BeExactly @('/set /subcategory:Logon /success:enable /failure:enable')
    }
    It 'makes no set call and reports unchanged when already enabled' {
        $a = Invoke-AuditScript -Setting 'Success and Failure' -Directions 'success'
        $a.Changed | Should -BeFalse
        @(Get-SetCall).Count | Should -Be 0
        @($script:AuditCalls | Where-Object { $_[0] -eq '/get' }).Count | Should -Be 1
    }
    It 'makes no set call in check mode but reports would-change' {
        $a = Invoke-AuditScript -Setting 'No Auditing' -Directions 'success' -CheckMode
        $a.Changed | Should -BeTrue
        @(Get-SetCall).Count | Should -Be 0
    }
    It 'never disables an existing other direction' {
        $a = Invoke-AuditScript -Setting 'Failure' -Directions 'success'
        $a.Changed | Should -BeTrue
        @(Get-SetCall) | Should -BeExactly @('/set /subcategory:Logon /success:enable')
        @($script:AuditCalls | ForEach-Object { $_ } | Where-Object { $_ -match 'disable' }).Count | Should -Be 0
    }
    It 'fails the task on a non-zero auditpol /set exit code' {
        { Invoke-AuditScript -Setting 'No Auditing' -Directions 'success' -SetExit 5 } | Should -Throw '*auditpol /set failed*'
    }
    It 'fails the task on a non-zero auditpol /get exit code without setting' {
        { Invoke-AuditScript -Setting 'Success' -Directions 'success' -GetExit 87 } | Should -Throw '*auditpol /get failed*'
        @(Get-SetCall).Count | Should -Be 0
    }
    It 'rejects an unknown direction before calling auditpol' {
        { Invoke-AuditScript -Setting 'Success' -Directions 'disable' } | Should -Throw '*unknown audit direction*'
        $script:AuditCalls.Count | Should -Be 0
    }
    It 'parses only stdout as CSV, so stderr text cannot become the header' {
        $a = Invoke-AuditScript -Setting 'Success' -Directions 'success' -GetStderr 'Machine Name,Bogus'
        $a.Changed | Should -BeFalse
        @(Get-SetCall).Count | Should -Be 0
    }
    It 'includes stderr in the failure message on a non-zero /get exit' {
        { Invoke-AuditScript -Setting 'Success' -Directions 'success' -GetExit 87 -GetStderr 'Error 0x00000057 occurred' } |
            Should -Throw '*Error 0x00000057 occurred*'
    }
    It 'reads the inclusion setting exactly as ConvertFrom-AuditPolCsv does (<Setting>)' -TestCases @(
        @{ Setting = 'No Auditing' }
        @{ Setting = 'Success' }
        @{ Setting = 'Failure' }
        @{ Setting = 'Success and Failure' }
        @{ Setting = '' }
    ) {
        $csv = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting`nHOST,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},$Setting,"
        $woscap = InModuleScope woscap -Parameters @{ Csv = $csv } { @((ConvertFrom-AuditPolCsv -CsvText $Csv)['Logon'] | ForEach-Object { $_.ToLowerInvariant() }) }
        # Ask for both directions: whatever the script does not enable, it judged present.
        $null = Invoke-AuditScript -Setting $Setting -Directions 'success', 'failure'
        $set = "$(Get-SetCall)"
        $present = @(@('success', 'failure') | Where-Object { $set -notmatch "/$($_):enable" })
        @($present | Sort-Object) | Should -Be @($woscap | Sort-Object)
    }
}

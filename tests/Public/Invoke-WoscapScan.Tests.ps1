BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Fixture = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/sample-xccdf.xml'
    $script:Pack    = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/contentpack'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-WoscapScan' {
    It 'is exported as a public command' {
        Get-Command Invoke-WoscapScan -Module woscap | Should -Not -BeNullOrEmpty
    }
    It 'returns one RuleResult per rule and evaluates the fixture end-to-end' {
        # Fixture pack: WNTEST-00-000010 = Registry Foo eq 1; WNTEST-00-000020 = ScriptBlock 'Pass';
        # WNTEST-00-000030 has no authored check -> Not_Reviewed.
        Mock -ModuleName woscap Get-RegValue { 1 }
        $res = Invoke-WoscapScan -XccdfPath $script:Fixture -ContentPath $script:Pack -Quiet
        @($res).Count | Should -Be 3
        ($res | Where-Object StigId -eq 'WNTEST-00-000010').Status | Should -Be 'NotAFinding'
        ($res | Where-Object StigId -eq 'WNTEST-00-000020').Status | Should -Be 'NotAFinding'
        ($res | Where-Object StigId -eq 'WNTEST-00-000030').Status | Should -Be 'Not_Reviewed'
    }
    It 'writes a JSON report when -JsonPath is given' {
        Mock -ModuleName woscap Get-RegValue { 1 }
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ("woscap-" + [System.Guid]::NewGuid() + ".json")
        try {
            Invoke-WoscapScan -XccdfPath $script:Fixture -ContentPath $script:Pack -JsonPath $out -Quiet | Out-Null
            Test-Path $out | Should -BeTrue
            (Get-Content $out -Raw | ConvertFrom-Json).Count | Should -Be 3
        } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
    }
    It 'serializes a single-result scan as a JSON array (not a bare object)' {
        $single = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/single-rule-xccdf.xml'
        $emptyPack = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid())
        New-Item -ItemType Directory -Path $emptyPack | Out-Null
        $out = Join-Path ([System.IO.Path]::GetTempPath()) ("woscap-" + [System.Guid]::NewGuid() + ".json")
        try {
            $res = Invoke-WoscapScan -XccdfPath $single -ContentPath $emptyPack -JsonPath $out -Quiet
            @($res).Count | Should -Be 1
            (Get-Content $out -Raw).TrimStart()[0] | Should -Be '['   # array, not '{'
        } finally {
            Remove-Item $out -Force -ErrorAction SilentlyContinue
            Remove-Item $emptyPack -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    It 'emits results enumerated so pipeline filtering works per-rule' {
        Mock -ModuleName woscap Get-RegValue { 1 }
        $nr = Invoke-WoscapScan -XccdfPath $script:Fixture -ContentPath $script:Pack -Quiet |
            Where-Object Status -eq 'Not_Reviewed'
        @($nr).Count | Should -Be 1   # only WNTEST-00-000030 has no authored check
    }
    It 'applies an exception profile via -ProfilePath' {
        $prof = Join-Path ([System.IO.Path]::GetTempPath()) ("prof-" + [System.Guid]::NewGuid() + ".psd1")
        Set-Content -LiteralPath $prof -Value "@{ 'WNTEST-00-000030' = @{ Type = 'NotApplicable'; Justification = 'n/a' } }"
        try {
            Mock -ModuleName woscap Get-RegValue { 1 }
            $res = Invoke-WoscapScan -XccdfPath $script:Fixture -ContentPath $script:Pack -ProfilePath $prof -Quiet
            ($res | Where-Object StigId -eq 'WNTEST-00-000030').Status | Should -Be 'Not_Applicable'
        } finally { Remove-Item $prof -Force -ErrorAction SilentlyContinue }
    }

    It 'runs in-process (no remoting) when -ComputerName is localhost' {
        Mock -ModuleName woscap Get-RegValue { 1 }
        Mock -ModuleName woscap Invoke-WoscapRemoteScan { throw 'remote path should not be taken' }
        $res = Invoke-WoscapScan -XccdfPath $script:Fixture -ContentPath $script:Pack -ComputerName 'localhost' -Quiet
        @($res).Count | Should -Be 3
        Should -Not -Invoke Invoke-WoscapRemoteScan -ModuleName woscap -Scope It
    }

    It 'delegates to Invoke-WoscapRemoteScan when a remote host is given' {
        Mock -ModuleName woscap Invoke-WoscapRemoteScan { @([pscustomobject]@{ Host = 'SRV01'; StigId = 'S1'; Status = 'Open'; Severity = 'high'; Exception = $null }) }
        Mock -ModuleName woscap Invoke-CheckEval { throw 'local path should not be taken' }
        $res = Invoke-WoscapScan -XccdfPath $script:Fixture -ContentPath $script:Pack -ComputerName 'SRV01' -Quiet
        Should -Invoke Invoke-WoscapRemoteScan -ModuleName woscap -Times 1 -Scope It
        $res.Host | Should -Be 'SRV01'
    }

    It 'scans localhost in-process AND remote hosts when the list mixes both' {
        Mock -ModuleName woscap Get-RegValue { 1 }
        Mock -ModuleName woscap Invoke-WoscapRemoteScan { @([pscustomobject]@{ Host = 'SRV01'; StigId = 'S9'; Status = 'Open'; Severity = 'high'; Exception = $null }) }
        $res = Invoke-WoscapScan -XccdfPath $script:Fixture -ContentPath $script:Pack -ComputerName 'localhost','SRV01' -Quiet
        Should -Invoke Invoke-WoscapRemoteScan -ModuleName woscap -Times 1 -Scope It
        @($res | Where-Object Host -eq 'SRV01').Count | Should -Be 1
        @($res).Count | Should -Be 4   # 3 local fixture rules + 1 remote
    }

    It 'deduplicates repeated remote hosts before fanning out' {
        Mock -ModuleName woscap Invoke-WoscapRemoteScan { @($ComputerName | ForEach-Object { [pscustomobject]@{ Host = $_; StigId = 'S1'; Status = 'Open'; Severity = 'high'; Exception = $null } }) }
        Invoke-WoscapScan -XccdfPath $script:Fixture -ContentPath $script:Pack -ComputerName 'SRV01','SRV01' -Quiet | Out-Null
        Should -Invoke Invoke-WoscapRemoteScan -ModuleName woscap -ParameterFilter { @($ComputerName).Count -eq 1 } -Times 1 -Scope It
    }

    It 'fails fast when the content-pack path does not exist' {
        { Invoke-WoscapScan -XccdfPath $script:Fixture -ContentPath 'C:\woscap-nope-does-not-exist' -Quiet } | Should -Throw
    }
}

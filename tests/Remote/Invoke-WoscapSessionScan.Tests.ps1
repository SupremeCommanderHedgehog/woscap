BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-WoscapSessionScan' {
    It 'copies the module into the session and returns the engine results' {
        InModuleScope woscap {
            $session = [pscustomobject]@{ ComputerName = 'SRV01' }
            $canned  = @([pscustomobject]@{ Host = 'SRV01'; StigId = 'S1'; Status = 'Open' })
            Mock Invoke-WoscapRemoteCommand -ParameterFilter { $ScriptBlock -match 'New-Item' }       { 'C:\Temp\woscap_test' }
            Mock Invoke-WoscapRemoteCommand -ParameterFilter { $ScriptBlock -match 'Invoke-CheckEval' } { $canned }
            Mock Invoke-WoscapRemoteCommand -ParameterFilter { $ScriptBlock -match 'Remove-Item' }     { }
            Mock Copy-WoscapModuleToSession { }

            $res = Invoke-WoscapSessionScan -Session $session -Rules @([pscustomobject]@{ StigId = 'S1' }) `
                -ExceptionProfile @{} -ModuleRoot 'C:\module' -Benchmark 'Windows11' -ContentPath 'C:\module\Content\Windows11'

            @($res).Count  | Should -Be 1
            $res[0].StigId | Should -Be 'S1'
            Should -Invoke Copy-WoscapModuleToSession -Times 1 -Scope It
            Should -Invoke Invoke-WoscapRemoteCommand -ParameterFilter { $ScriptBlock -match 'Invoke-CheckEval' } -Times 1 -Scope It
        }
    }

    It 'removes the remote temp directory after scanning (cleanup runs)' {
        InModuleScope woscap {
            $session = [pscustomobject]@{ ComputerName = 'SRV01' }
            Mock Invoke-WoscapRemoteCommand -ParameterFilter { $ScriptBlock -match 'New-Item' }       { 'C:\Temp\woscap_test' }
            Mock Invoke-WoscapRemoteCommand -ParameterFilter { $ScriptBlock -match 'Invoke-CheckEval' } { @() }
            Mock Invoke-WoscapRemoteCommand -ParameterFilter { $ScriptBlock -match 'Remove-Item' }     { }
            Mock Copy-WoscapModuleToSession { }

            Invoke-WoscapSessionScan -Session $session -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11'

            Should -Invoke Invoke-WoscapRemoteCommand -ParameterFilter { $ScriptBlock -match 'Remove-Item' } -Times 1 -Scope It
        }
    }
}

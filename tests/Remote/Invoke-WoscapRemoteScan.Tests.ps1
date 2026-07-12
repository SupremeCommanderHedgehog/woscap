BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-WoscapRemoteScan' {
    It 'aggregates RuleResult[] across reachable hosts' {
        InModuleScope woscap {
            Mock New-PSSession { @($ComputerName | ForEach-Object { [pscustomobject]@{ ComputerName = $_ } }) }
            Mock Invoke-WoscapSessionScan { @([pscustomobject]@{ Host = $Session.ComputerName; StigId = 'S1'; Status = 'Open' }) }
            Mock Remove-WoscapSession { }

            $res = Invoke-WoscapRemoteScan -ComputerName 'SRV01','SRV02' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11'

            @($res).Count   | Should -Be 2
            @($res.Host)    | Should -Contain 'SRV01'
            @($res.Host)    | Should -Contain 'SRV02'
        }
    }

    It 'emits one Not_Reviewed result for an unreachable host and still scans the others' {
        InModuleScope woscap {
            Mock New-PSSession { @($ComputerName | Where-Object { $_ -ne 'SRV02' } | ForEach-Object { [pscustomobject]@{ ComputerName = $_ } }) }
            Mock Invoke-WoscapSessionScan { @([pscustomobject]@{ Host = $Session.ComputerName; StigId = 'S1'; Status = 'NotAFinding' }) }
            Mock Remove-WoscapSession { }

            $res = Invoke-WoscapRemoteScan -ComputerName 'SRV01','SRV02' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11' -WarningAction SilentlyContinue

            $bad = @($res | Where-Object Host -eq 'SRV02')
            @($bad).Count  | Should -Be 1
            $bad[0].Status | Should -Be 'Not_Reviewed'
            $bad[0].StigId | Should -BeNullOrEmpty
            (@($res | Where-Object Host -eq 'SRV01')).Count | Should -Be 1
        }
    }

    It 'turns a per-host scan failure into a Not_Reviewed result and continues the batch' {
        InModuleScope woscap {
            Mock New-PSSession { @($ComputerName | ForEach-Object { [pscustomobject]@{ ComputerName = $_ } }) }
            Mock Invoke-WoscapSessionScan {
                if ($Session.ComputerName -eq 'SRV02') { throw 'scan blew up' }
                @([pscustomobject]@{ Host = $Session.ComputerName; StigId = 'S1'; Status = 'Open' })
            }
            Mock Remove-WoscapSession { }

            $res = Invoke-WoscapRemoteScan -ComputerName 'SRV01','SRV02' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11' -WarningAction SilentlyContinue

            (@($res | Where-Object { $_.Host -eq 'SRV02' -and $_.Status -eq 'Not_Reviewed' })).Count | Should -Be 1
            (@($res | Where-Object { $_.Host -eq 'SRV01' -and $_.Status -eq 'Open' })).Count         | Should -Be 1
        }
    }

    It 'removes the opened sessions (cleanup)' {
        InModuleScope woscap {
            Mock New-PSSession { @($ComputerName | ForEach-Object { [pscustomobject]@{ ComputerName = $_ } }) }
            Mock Invoke-WoscapSessionScan { @() }
            Mock Remove-WoscapSession { }

            Invoke-WoscapRemoteScan -ComputerName 'SRV01','SRV02' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11'

            Should -Invoke Remove-WoscapSession -Times 1 -Scope It
        }
    }

    It 'does not inject a null result when a host returns nothing (zero-rule no-op)' {
        InModuleScope woscap {
            Mock New-PSSession { @($ComputerName | ForEach-Object { [pscustomobject]@{ ComputerName = $_ } }) }
            # A zero-rule host returns nothing; the worker emits $null, not @().
            Mock Invoke-WoscapSessionScan { return $null }
            Mock Remove-WoscapSession { }

            $res = Invoke-WoscapRemoteScan -ComputerName 'SRV01','SRV02' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11'

            @($res).Count | Should -Be 0
            @($res | Where-Object { $null -eq $_ }).Count | Should -Be 0
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-WoscapRemoteScan' {
    It 'aggregates RuleResult[] across reachable hosts' {
        InModuleScope woscap {
            Mock New-PSSession { @($ComputerName | ForEach-Object { [pscustomobject]@{ ComputerName = $_ } }) }
            Mock Push-WoscapScanPayload { }
            Mock Remove-WoscapScanPayload { }
            Mock Remove-WoscapSession { }
            Mock Invoke-WoscapBatchedScan {
                [pscustomobject]@{
                    Results  = @($Session | ForEach-Object { [pscustomobject]@{ Host = $_.ComputerName; StigId = 'S1'; Status = 'Open' } })
                    Failures = @{}
                }
            }

            $res = Invoke-WoscapRemoteScan -ComputerName 'SRV01','SRV02' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11'

            @($res).Count | Should -Be 2
            @($res.Host)  | Should -Contain 'SRV01'
            @($res.Host)  | Should -Contain 'SRV02'
        }
    }

    It 'emits one Not_Reviewed for an unreachable host and still scans the others' {
        InModuleScope woscap {
            Mock New-PSSession { @($ComputerName | Where-Object { $_ -ne 'SRV02' } | ForEach-Object { [pscustomobject]@{ ComputerName = $_ } }) }
            Mock Push-WoscapScanPayload { }
            Mock Remove-WoscapScanPayload { }
            Mock Remove-WoscapSession { }
            Mock Invoke-WoscapBatchedScan {
                [pscustomobject]@{
                    Results  = @($Session | ForEach-Object { [pscustomobject]@{ Host = $_.ComputerName; StigId = 'S1'; Status = 'NotAFinding' } })
                    Failures = @{}
                }
            }

            $res = Invoke-WoscapRemoteScan -ComputerName 'SRV01','SRV02' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11' -WarningAction SilentlyContinue

            $bad = @($res | Where-Object Host -eq 'SRV02')
            @($bad).Count  | Should -Be 1
            $bad[0].Status | Should -Be 'Not_Reviewed'
            $bad[0].StigId | Should -BeNullOrEmpty
            (@($res | Where-Object Host -eq 'SRV01')).Count | Should -Be 1
        }
    }

    It 'treats an FQDN session as reachable for a short-name request (no false flag)' {
        InModuleScope woscap {
            Mock New-PSSession { @([pscustomobject]@{ ComputerName = 'SRV01.corp.local' }) }
            Mock Push-WoscapScanPayload { }
            Mock Remove-WoscapScanPayload { }
            Mock Remove-WoscapSession { }
            Mock Invoke-WoscapBatchedScan {
                [pscustomobject]@{
                    Results  = @([pscustomobject]@{ Host = 'SRV01.corp.local'; StigId = 'S1'; Status = 'Open' })
                    Failures = @{}
                }
            }

            $res = Invoke-WoscapRemoteScan -ComputerName 'SRV01' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11' -WarningAction SilentlyContinue

            (@($res | Where-Object { $_.Status -eq 'Not_Reviewed' })).Count | Should -Be 0
            (@($res | Where-Object { $_.Status -eq 'Open' })).Count         | Should -Be 1
        }
    }

    It 'flags a same-label sibling as unreachable (no short-label collision)' {
        InModuleScope woscap {
            # web.east connects; web.west is down. Both share the leading label 'web'.
            Mock New-PSSession { @([pscustomobject]@{ ComputerName = 'web.east.corp' }) }
            Mock Push-WoscapScanPayload { }
            Mock Remove-WoscapScanPayload { }
            Mock Remove-WoscapSession { }
            Mock Invoke-WoscapBatchedScan {
                [pscustomobject]@{
                    Results  = @($Session | ForEach-Object { [pscustomobject]@{ Host = $_.ComputerName; StigId = 'S1'; Status = 'Open' } })
                    Failures = @{}
                }
            }

            $res = Invoke-WoscapRemoteScan -ComputerName 'web.east.corp','web.west.corp' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11' -WarningAction SilentlyContinue

            (@($res | Where-Object { $_.Host -eq 'web.west.corp' -and $_.Status -eq 'Not_Reviewed' })).Count | Should -Be 1
            (@($res | Where-Object { $_.Host -eq 'web.east.corp' -and $_.Status -eq 'Open' })).Count         | Should -Be 1
        }
    }

    It 'compares IP-address targets exactly (no dotted-octet collision)' {
        InModuleScope woscap {
            # 10.0.0.5 connects; 10.9.9.9 is down. A first-octet split would collide both to '10'.
            Mock New-PSSession { @([pscustomobject]@{ ComputerName = '10.0.0.5' }) }
            Mock Push-WoscapScanPayload { }
            Mock Remove-WoscapScanPayload { }
            Mock Remove-WoscapSession { }
            Mock Invoke-WoscapBatchedScan {
                [pscustomobject]@{
                    Results  = @([pscustomobject]@{ Host = '10.0.0.5'; StigId = 'S1'; Status = 'Open' })
                    Failures = @{}
                }
            }

            $res = Invoke-WoscapRemoteScan -ComputerName '10.0.0.5','10.9.9.9' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11' -WarningAction SilentlyContinue

            (@($res | Where-Object { $_.Host -eq '10.9.9.9' -and $_.Status -eq 'Not_Reviewed' })).Count | Should -Be 1
            (@($res | Where-Object { $_.Host -eq '10.0.0.5' -and $_.Status -eq 'Open' })).Count         | Should -Be 1
        }
    }

    It 'turns a per-host scan failure into a Not_Reviewed and continues the batch' {
        InModuleScope woscap {
            Mock New-PSSession { @($ComputerName | ForEach-Object { [pscustomobject]@{ ComputerName = $_ } }) }
            Mock Push-WoscapScanPayload { }
            Mock Remove-WoscapScanPayload { }
            Mock Remove-WoscapSession { }
            Mock Invoke-WoscapBatchedScan {
                [pscustomobject]@{
                    Results  = @([pscustomobject]@{ Host = 'SRV01'; StigId = 'S1'; Status = 'Open' })
                    Failures = @{ 'SRV02' = 'scan blew up' }
                }
            }

            $res = Invoke-WoscapRemoteScan -ComputerName 'SRV01','SRV02' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11' -WarningAction SilentlyContinue

            (@($res | Where-Object { $_.Host -eq 'SRV02' -and $_.Status -eq 'Not_Reviewed' })).Count | Should -Be 1
            (@($res | Where-Object { $_.Host -eq 'SRV01' -and $_.Status -eq 'Open' })).Count         | Should -Be 1
        }
    }

    It 'handles an unreachable host and a scan-failing host in the same run without interference' {
        InModuleScope woscap {
            # SRV02 never connects; SRV01 + SRV03 do.
            Mock New-PSSession { @($ComputerName | Where-Object { $_ -ne 'SRV02' } | ForEach-Object { [pscustomobject]@{ ComputerName = $_ } }) }
            Mock Push-WoscapScanPayload { }
            Mock Remove-WoscapScanPayload { }
            Mock Remove-WoscapSession { }
            Mock Invoke-WoscapBatchedScan {
                [pscustomobject]@{
                    Results  = @([pscustomobject]@{ Host = 'SRV01'; StigId = 'S1'; Status = 'Open' })
                    Failures = @{ 'SRV03' = 'scan blew up' }
                }
            }

            $res = Invoke-WoscapRemoteScan -ComputerName 'SRV01','SRV02','SRV03' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11' -WarningAction SilentlyContinue

            # Exactly one Not_Reviewed for the unreachable host, one for the scan-failed host, one real result.
            (@($res | Where-Object { $_.Host -eq 'SRV02' -and $_.Status -eq 'Not_Reviewed' })).Count | Should -Be 1
            (@($res | Where-Object { $_.Host -eq 'SRV03' -and $_.Status -eq 'Not_Reviewed' })).Count | Should -Be 1
            (@($res | Where-Object { $_.Host -eq 'SRV01' -and $_.Status -eq 'Open' })).Count         | Should -Be 1
            (@($res | Where-Object { $_.Status -eq 'Not_Reviewed' })).Count | Should -Be 2
            @($res).Count | Should -Be 3
        }
    }

    It 'isolates a staging (ship) failure as a Not_Reviewed and still scans others' {
        InModuleScope woscap {
            Mock New-PSSession { @($ComputerName | ForEach-Object { [pscustomobject]@{ ComputerName = $_ } }) }
            Mock Push-WoscapScanPayload { if ($Session.ComputerName -eq 'SRV02') { throw 'copy failed' } }
            Mock Remove-WoscapScanPayload { }
            Mock Remove-WoscapSession { }
            Mock Invoke-WoscapBatchedScan {
                [pscustomobject]@{
                    Results  = @($Session | ForEach-Object { [pscustomobject]@{ Host = $_.ComputerName; StigId = 'S1'; Status = 'Open' } })
                    Failures = @{}
                }
            }

            $res = Invoke-WoscapRemoteScan -ComputerName 'SRV01','SRV02' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11' -WarningAction SilentlyContinue

            (@($res | Where-Object { $_.Host -eq 'SRV02' -and $_.Status -eq 'Not_Reviewed' })).Count | Should -Be 1
            (@($res | Where-Object { $_.Host -eq 'SRV01' -and $_.Status -eq 'Open' })).Count         | Should -Be 1
            Should -Invoke Invoke-WoscapBatchedScan -Times 1 -Scope It -ParameterFilter { @($Session).Count -eq 1 }
        }
    }

    It 'always cleans up temp dirs and sessions' {
        InModuleScope woscap {
            Mock New-PSSession { @($ComputerName | ForEach-Object { [pscustomobject]@{ ComputerName = $_ } }) }
            Mock Push-WoscapScanPayload { }
            Mock Remove-WoscapScanPayload { }
            Mock Remove-WoscapSession { }
            Mock Invoke-WoscapBatchedScan { [pscustomobject]@{ Results = @(); Failures = @{} } }

            Invoke-WoscapRemoteScan -ComputerName 'SRV01','SRV02' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11'

            Should -Invoke Remove-WoscapScanPayload -Times 1 -Scope It
            Should -Invoke Remove-WoscapSession    -Times 1 -Scope It
        }
    }

    It 'does not inject a null result when a host returns nothing (zero-rule no-op)' {
        InModuleScope woscap {
            Mock New-PSSession { @($ComputerName | ForEach-Object { [pscustomobject]@{ ComputerName = $_ } }) }
            Mock Push-WoscapScanPayload { }
            Mock Remove-WoscapScanPayload { }
            Mock Remove-WoscapSession { }
            Mock Invoke-WoscapBatchedScan { [pscustomobject]@{ Results = @($null); Failures = @{} } }

            $res = Invoke-WoscapRemoteScan -ComputerName 'SRV01','SRV02' -Rules @() -ExceptionProfile @{} `
                -ModuleRoot 'C:\m' -Benchmark 'Windows11' -ContentPath 'C:\m\Content\Windows11'

            @($res).Count | Should -Be 0
            @($res | Where-Object { $null -eq $_ }).Count | Should -Be 0
        }
    }
}

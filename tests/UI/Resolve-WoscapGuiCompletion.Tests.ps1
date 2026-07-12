BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Resolve-WoscapGuiCompletion' {
    It 'reports None when there are no errors' {
        InModuleScope woscap {
            $c = Resolve-WoscapGuiCompletion -Results @([pscustomobject]@{ StigId = 'V-1' }) -ErrorRecords @()
            $c.Kind | Should -Be 'None'
        }
    }

    It 'reports a Warning (not a failure) when results were delivered alongside non-terminating errors' {
        InModuleScope woscap {
            # 2 of 3 hosts succeeded, 1 unreachable -> results present + one error record.
            $c = Resolve-WoscapGuiCompletion `
                -Results      @([pscustomobject]@{ Host = 'H1' }, [pscustomobject]@{ Host = 'H2' }) `
                -ErrorRecords @('SRV03 unreachable')
            $c.Kind    | Should -Be 'Warning'
            $c.Count   | Should -Be 1
            $c.Message | Should -Match 'SRV03 unreachable'
        }
    }

    It 'counts Warning-stream records (e.g. an unreachable host) as warnings when results were delivered' {
        InModuleScope woscap {
            # The remote fan-out reports a failed host via Write-Warning + a synthetic result
            # row, NOT the Error stream -- the classifier must see the Warning stream too (#45).
            $c = Resolve-WoscapGuiCompletion `
                -Results        @([pscustomobject]@{ Host = 'H1' }, [pscustomobject]@{ Host = 'H2' }) `
                -ErrorRecords   @() `
                -WarningRecords @("woscap: host 'SRV03' unreachable")
            $c.Kind    | Should -Be 'Warning'
            $c.Count   | Should -Be 1
            $c.Message | Should -Match 'SRV03'
        }
    }

    It 'combines error-stream and warning-stream records into the count and detail' {
        InModuleScope woscap {
            $c = Resolve-WoscapGuiCompletion -Results @([pscustomobject]@{ Host = 'H1' }) `
                -ErrorRecords @('pipeline error') -WarningRecords @('host down')
            $c.Kind    | Should -Be 'Warning'
            $c.Count   | Should -Be 2
            $c.Message | Should -Match 'pipeline error'
            $c.Message | Should -Match 'host down'
        }
    }

    It 'reports an Error when errors occurred and NO results came back' {
        InModuleScope woscap {
            $c = Resolve-WoscapGuiCompletion -Results @() -ErrorRecords @('everything failed')
            $c.Kind    | Should -Be 'Error'
            $c.Message | Should -Match 'everything failed'
        }
    }

    It 'joins accumulated non-terminating errors onto a terminating error message' {
        InModuleScope woscap {
            # The terminating exception explains the abort; the per-host detail explains WHY.
            $c = Resolve-WoscapGuiCompletion -Results @() `
                -ErrorRecords @('host A: access denied', 'host B: timeout') `
                -TerminatingError 'Scan aborted'
            $c.Kind    | Should -Be 'Error'
            $c.Message | Should -Match 'Scan aborted'
            $c.Message | Should -Match 'access denied'
            $c.Message | Should -Match 'timeout'
        }
    }

    It 'uses the terminating error alone when there is no accumulated detail' {
        InModuleScope woscap {
            $c = Resolve-WoscapGuiCompletion -Results @() -ErrorRecords @() -TerminatingError 'boom'
            $c.Kind    | Should -Be 'Error'
            $c.Message | Should -Be 'boom'
        }
    }

    It 'joins multiple error records with newlines' {
        InModuleScope woscap {
            $c = Resolve-WoscapGuiCompletion -Results @([pscustomobject]@{ Host = 'H1' }) `
                -ErrorRecords @('first', 'second')
            $c.Kind    | Should -Be 'Warning'
            $c.Count   | Should -Be 2
            $c.Message | Should -Be "first`nsecond"
        }
    }
}

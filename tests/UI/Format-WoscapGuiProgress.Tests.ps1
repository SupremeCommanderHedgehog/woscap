BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Format-WoscapGuiProgress' {
    It 'maps a determinate record to percent + status text' {
        InModuleScope woscap {
            $rec = [System.Management.Automation.ProgressRecord]::new(1, 'Evaluating STIG rules', '142 of 300')
            $rec.PercentComplete = 47
            $f = Format-WoscapGuiProgress -Record $rec
            $f.Percent       | Should -Be 47
            $f.Text          | Should -Be '142 of 300'
            $f.Indeterminate | Should -BeFalse
        }
    }
    It 'flags a negative percent as indeterminate and clamps to 0' {
        InModuleScope woscap {
            $rec = [System.Management.Automation.ProgressRecord]::new(1, 'Scanning', 'Working')
            $rec.PercentComplete = -1
            $f = Format-WoscapGuiProgress -Record $rec
            $f.Percent       | Should -Be 0
            $f.Indeterminate | Should -BeTrue
        }
    }
    It 'returns nothing for a -Completed record so the final frame is not rendered as a marquee' {
        InModuleScope woscap {
            # The engine's terminating Write-Progress -Completed carries PercentComplete=-1,
            # which would otherwise flip the bar to Marquee for one poll before OnComplete
            # resets it (#46). A Completed record must render nothing.
            $rec = [System.Management.Automation.ProgressRecord]::new(1, 'Evaluating STIG rules', 'done')
            $rec.RecordType = [System.Management.Automation.ProgressRecordType]::Completed
            Format-WoscapGuiProgress -Record $rec | Should -BeNullOrEmpty
        }
    }
    It 'falls back to Activity when StatusDescription is blank' {
        InModuleScope woscap {
            $rec = [System.Management.Automation.ProgressRecord]::new(1, 'Evaluating STIG rules', 'x')
            $rec.StatusDescription = ' '
            $rec.PercentComplete = 10
            (Format-WoscapGuiProgress -Record $rec).Text | Should -Be 'Evaluating STIG rules'
        }
    }
}

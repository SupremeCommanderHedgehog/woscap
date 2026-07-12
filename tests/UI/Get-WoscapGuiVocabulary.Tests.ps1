BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapGuiVocabulary' {
    It 'derives the severity list from New-WoscapResult so it cannot drift' {
        InModuleScope woscap {
            $canonical = ((Get-Command New-WoscapResult).Parameters['Severity'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }).ValidValues
            (Get-WoscapGuiVocabulary).Severity | Should -Be @($canonical)
        }
    }

    It 'derives the export-format list from Export-WoscapResult so it cannot drift' {
        InModuleScope woscap {
            $canonical = ((Get-Command Export-WoscapResult).Parameters['Format'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }).ValidValues
            (Get-WoscapGuiVocabulary).Format | Should -Be @($canonical)
        }
    }

    It 'derives the status list from ConvertTo-WoscapStatus display values (distinct)' {
        InModuleScope woscap {
            $codes = ((Get-Command ConvertTo-WoscapStatus).Parameters['Result'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }).ValidValues
            $expected = @($codes | ForEach-Object { ConvertTo-WoscapStatus -Result $_ } | Select-Object -Unique)
            (Get-WoscapGuiVocabulary).Status | Should -Be $expected
        }
    }

    It 'does not bake the GUI-only All prefix into any list' {
        InModuleScope woscap {
            $v = Get-WoscapGuiVocabulary
            $v.Severity | Should -Not -Contain 'All'
            $v.Status   | Should -Not -Contain 'All'
            $v.Format   | Should -Not -Contain 'All'
        }
    }
}

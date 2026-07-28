BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Expensive reads are cached per scan' {
    It 'exports the security policy once across many SecEdit reads' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            Mock ConvertFrom-SecEditInf { @{ 'System Access' = @{ 'MinimumPasswordLength' = 14 } } }
            Mock Invoke-SecEditExport -MockWith { '[System Access]' }
            $null = Get-SecEditSetting -Name 'MinimumPasswordLength'
            $null = Get-SecEditSetting -Name 'MinimumPasswordLength'
            $null = Get-SecEditSetting -Name 'MinimumPasswordLength'
            Should -Invoke Invoke-SecEditExport -Times 3 -Exactly
        }
    }
    It 'runs auditpol once across many AuditPolicy reads' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            $script:polHits = 0
            Mock Invoke-AuditPolRaw { $script:polHits++; 'csv' }
            Mock ConvertFrom-AuditPolCsv { @{ 'Logon' = @('Success') } }
            $null = Get-AuditPolicy -Subcategory 'Logon'
            $null = Get-AuditPolicy -Subcategory 'Logon'
            $script:polHits | Should -Be 1
        }
    }
    It 'runs secedit.exe once across many raw exports' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            $script:secHits = 0
            Mock Invoke-SecEditExportRaw { $script:secHits++; '[System Access]' }
            $null = Invoke-SecEditExport
            $null = Invoke-SecEditExport
            $null = Invoke-SecEditExport
            $script:secHits | Should -Be 1
        }
    }
    It 'starts fresh after the cache is cleared' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            $script:secHits = 0
            Mock Invoke-SecEditExportRaw { $script:secHits++; '[System Access]' }
            $null = Invoke-SecEditExport
            Clear-WoscapReadCache
            $null = Invoke-SecEditExport
            $script:secHits | Should -Be 2
        }
    }
}

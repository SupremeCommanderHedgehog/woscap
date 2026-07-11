BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-UserRight' {
    It 'returns the SID list for a privilege' {
        InModuleScope woscap {
            Mock Invoke-SecEditExport { "[Privilege Rights]`r`nSeBackupPrivilege = *S-1-5-32-544" }
            Get-UserRight -Privilege 'SeBackupPrivilege' | Should -Be @('*S-1-5-32-544')
        }
    }
    It 'returns an empty array when the privilege is unassigned' {
        InModuleScope woscap {
            Mock Invoke-SecEditExport { "[Privilege Rights]`r`nSeBackupPrivilege = *S-1-5-32-544" }
            (Get-UserRight -Privilege 'SeTcbPrivilege').Count | Should -Be 0
        }
    }
}

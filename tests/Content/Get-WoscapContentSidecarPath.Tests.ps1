BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapContentSidecarPath' {
    It 'derives the sidecar path under the revision directory' {
        InModuleScope woscap {
            Get-WoscapContentSidecarPath -RevisionDir 'C:\cache\Windows11\1' |
                Should -Be (Join-Path 'C:\cache\Windows11\1' '.woscap-content.json')
        }
    }
}

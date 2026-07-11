BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-AclSetting' {
    It 'returns access entries as identity/rights pairs' {
        InModuleScope woscap {
            Mock Get-Acl {
                [pscustomobject]@{ Access = @(
                    [pscustomobject]@{ IdentityReference='BUILTIN\Administrators'; FileSystemRights='FullControl'; AccessControlType='Allow' }
                ) }
            }
            $a = Get-AclSetting -Path 'C:\Windows'
            $a[0].Identity | Should -Be 'BUILTIN\Administrators'
            $a[0].Rights   | Should -Be 'FullControl'
        }
    }
    It 'returns $null when the path cannot be read' {
        InModuleScope woscap {
            Mock Get-Acl { throw 'denied' }
            Get-AclSetting -Path 'C:\Nope' | Should -BeNullOrEmpty
        }
    }
}

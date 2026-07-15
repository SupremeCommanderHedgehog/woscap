BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-AuditPolSet' {
    It 'enables success and disables failure per the flags (no real auditpol call)' {
        InModuleScope woscap {
            $script:captured = $null
            Mock Invoke-AuditPolNative { $script:captured = $Arguments }
            Invoke-AuditPolSet -Subcategory 'Logon' -Success $true -Failure $false
            Should -Invoke Invoke-AuditPolNative -Exactly 1
            $script:captured | Should -Be @('/set','/subcategory:Logon','/success:enable','/failure:disable')
        }
    }
    It 'enables both directions when both are required' {
        InModuleScope woscap {
            $script:captured = $null
            Mock Invoke-AuditPolNative { $script:captured = $Arguments }
            Invoke-AuditPolSet -Subcategory 'Credential Validation' -Success $true -Failure $true
            $script:captured | Should -Be @('/set','/subcategory:Credential Validation','/success:enable','/failure:enable')
        }
    }
    It 'propagates a native failure (per-rule isolation happens in the cmdlet)' {
        InModuleScope woscap {
            Mock Invoke-AuditPolNative { throw 'auditpol failed (exit 1)' }
            { Invoke-AuditPolSet -Subcategory 'Logon' -Success $true -Failure $true } | Should -Throw
        }
    }
}

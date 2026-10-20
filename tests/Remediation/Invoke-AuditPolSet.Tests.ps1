BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-AuditPolSet' {
    It 'enables only the required direction and leaves the other untouched (no real auditpol call)' {
        InModuleScope woscap {
            $script:captured = $null
            Mock Invoke-AuditPolNative { $script:captured = $Arguments }
            Invoke-AuditPolSet -Subcategory 'Logon' -Success $true -Failure $false
            Should -Invoke Invoke-AuditPolNative -Exactly 1
            $script:captured | Should -Be @('/set','/subcategory:Logon','/success:enable')
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
    It 'never produces a disable argument for any single-direction request' -ForEach @(
        @{ Success = $true;  Failure = $false; Want = '/success:enable' }
        @{ Success = $false; Failure = $true;  Want = '/failure:enable' }
    ) {
        InModuleScope woscap -Parameters @{ S = $Success; F = $Failure; Want = $Want } {
            param($S, $F, $Want)
            $script:captured = $null
            Mock Invoke-AuditPolNative { $script:captured = $Arguments }
            Invoke-AuditPolSet -Subcategory 'Logon' -Success $S -Failure $F
            @($script:captured | Where-Object { $_ -match 'disable' }).Count | Should -Be 0
            @($script:captured | Where-Object { $_ -match '^/(success|failure):' }) | Should -Be @($Want)
        }
    }
    It 'refuses a request with no direction to enable and calls nothing' {
        InModuleScope woscap {
            Mock Invoke-AuditPolNative { }
            { Invoke-AuditPolSet -Subcategory 'Logon' -Success $false -Failure $false } | Should -Throw
            Should -Invoke Invoke-AuditPolNative -Exactly 0
        }
    }
    It 'propagates a native failure (per-rule isolation happens in the cmdlet)' {
        InModuleScope woscap {
            Mock Invoke-AuditPolNative { throw 'auditpol failed (exit 1)' }
            { Invoke-AuditPolSet -Subcategory 'Logon' -Success $true -Failure $true } | Should -Throw
        }
    }
}

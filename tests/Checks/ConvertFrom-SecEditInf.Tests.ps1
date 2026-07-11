BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Inf = @'
[System Access]
MinimumPasswordLength = 14
PasswordComplexity = 1
[Privilege Rights]
SeDenyNetworkLogonRight = *S-1-5-32-546,*S-1-5-113
SeBackupPrivilege = *S-1-5-32-544
'@
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'ConvertFrom-SecEditInf' {
    It 'parses a section value' {
        InModuleScope woscap -Parameters @{ Inf = $script:Inf } {
            $p = ConvertFrom-SecEditInf -InfText $Inf
            $p['System Access']['MinimumPasswordLength'] | Should -Be '14'
        }
    }
    It 'parses privilege-rights SID lists into arrays' {
        InModuleScope woscap -Parameters @{ Inf = $script:Inf } {
            $p = ConvertFrom-SecEditInf -InfText $Inf
            $p['Privilege Rights']['SeDenyNetworkLogonRight'] | Should -Be @('*S-1-5-32-546','*S-1-5-113')
        }
    }
    It 'preserves earlier keys when a section header repeats' {
        InModuleScope woscap {
            $inf = "[System Access]`r`nMinimumPasswordLength = 14`r`n[System Access]`r`nPasswordComplexity = 1"
            $p = ConvertFrom-SecEditInf -InfText $inf
            $p['System Access']['MinimumPasswordLength'] | Should -Be '14'
            $p['System Access']['PasswordComplexity']    | Should -Be '1'
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force

    # New-Rule wraps a check-text as a parsed-rule object (only .CheckText / .StigId matter here).
    # Defined in module scope so it resolves inside the It blocks' InModuleScope.
    InModuleScope woscap {
        function script:New-Rule { param([string] $CheckText) [pscustomobject]@{ StigId = 'EDGE-00-000006'; CheckText = $CheckText } }
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'ConvertTo-WoscapCheckDescriptor (Edge-format inline registry)' {
    It 'extracts a REG_DWORD eq descriptor with a quoted value name' {
        InModuleScope woscap {
            $ct = 'The policy value for "Computer Configuration/.../Continue running background apps" must be set to "Disabled". Use the Windows Registry Editor to navigate to the following key: HKLM\SOFTWARE\Policies\Microsoft\Edge  If the value for "BackgroundModeEnabled" is not set to "REG_DWORD = 0", this is a finding.'
            $d = ConvertTo-WoscapCheckDescriptor -Rule (New-Rule $ct)
            $d.Type     | Should -Be 'Registry'
            $d.Path     | Should -Be 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
            $d.Name     | Should -Be 'BackgroundModeEnabled'
            $d.Operator | Should -Be 'eq'
            $d.Expected | Should -Be 0
            $d.Expected | Should -BeOfType [int]
        }
    }

    It 'handles an unquoted value name' {
        InModuleScope woscap {
            $ct = 'Use the Windows Registry Editor to navigate to the following key: HKLM\SOFTWARE\Policies\Microsoft\Edge  If the value for DefaultPopupsSetting is not set to "REG_DWORD = 2", this is a finding.'
            $d = ConvertTo-WoscapCheckDescriptor -Rule (New-Rule $ct)
            $d.Name     | Should -Be 'DefaultPopupsSetting'
            $d.Expected | Should -Be 2
        }
    }

    It 'keeps a REG_SZ value as a string, including embedded commas' {
        InModuleScope woscap {
            $ct = 'Use the Windows Registry Editor to navigate to the following key: HKLM\SOFTWARE\Policies\Microsoft\Edge  If the value for "AuthSchemes" is not set to "REG_SZ = ntlm,negotiate", this is a finding.'
            $d = ConvertTo-WoscapCheckDescriptor -Rule (New-Rule $ct)
            $d.Expected | Should -Be 'ntlm,negotiate'
            $d.Expected | Should -BeOfType [string]
        }
    }

    It 'strips typographic (curly) quotes around the value name' {
        InModuleScope woscap {
            $ct = "Use the Windows Registry Editor to navigate to the following key: HKLM\SOFTWARE\Policies\Microsoft\Edge  If the value for $([char]0x201C)DefaultCookiesSetting$([char]0x201D) is not set to `"REG_DWORD = 4`", this is a finding."
            (ConvertTo-WoscapCheckDescriptor -Rule (New-Rule $ct)).Name | Should -Be 'DefaultCookiesSetting'
        }
    }

    It 'maps an HKCU key to the HKCU: prefix' {
        InModuleScope woscap {
            $ct = 'Use the Windows Registry Editor to navigate to the following key: HKCU\SOFTWARE\Policies\Microsoft\Edge  If the value for "Example" is not set to "REG_DWORD = 1", this is a finding.'
            (ConvertTo-WoscapCheckDescriptor -Rule (New-Rule $ct)).Path | Should -Be 'HKCU:\SOFTWARE\Policies\Microsoft\Edge'
        }
    }

    It 'returns $null for a purely numeric value name (a list-subkey entry, not a scalar)' {
        InModuleScope woscap {
            $ct = 'Use the Windows Registry Editor to navigate to the following key: HKLM\SOFTWARE\Policies\Microsoft\Edge\URLAllowlist  If the value for "1" is not set to "REG_SZ = *", this is a finding.'
            ConvertTo-WoscapCheckDescriptor -Rule (New-Rule $ct) | Should -BeNullOrEmpty
        }
    }

    It 'returns $null for a Group-Policy-only rule with no registry key/value stated' {
        InModuleScope woscap {
            $ct = 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Proxy server/Proxy Settings" must be "Enabled". Consult Microsoft documentation. If it is not, this is a finding.'
            ConvertTo-WoscapCheckDescriptor -Rule (New-Rule $ct) | Should -BeNullOrEmpty
        }
    }

    It 'returns $null for a version cross-reference (manual) rule' {
        InModuleScope woscap {
            $ct = 'Cross-reference the build information displayed with the Microsoft Edge site to identify the oldest supported build. If the installed version is not supported, this is a finding.'
            ConvertTo-WoscapCheckDescriptor -Rule (New-Rule $ct) | Should -BeNullOrEmpty
        }
    }

    It 'fails closed on a multi-value range instead of taking the first integer' {
        InModuleScope woscap {
            $ct = 'Use the Windows Registry Editor to navigate to the following key: HKLM\SOFTWARE\Policies\Microsoft\Edge  If the value for "SomeSetting" is not set to "REG_DWORD = 1 or 2", this is a finding.'
            ConvertTo-WoscapCheckDescriptor -Rule (New-Rule $ct) | Should -BeNullOrEmpty
        }
    }

    It 'returns $null for a REG_MULTI_SZ value (a string array, not a scalar eq)' {
        InModuleScope woscap {
            $ct = 'Use the Windows Registry Editor to navigate to the following key: HKLM\SOFTWARE\Policies\Microsoft\Edge  If the value for "SomeList" is not set to "REG_MULTI_SZ = a,b,c", this is a finding.'
            ConvertTo-WoscapCheckDescriptor -Rule (New-Rule $ct) | Should -BeNullOrEmpty
        }
    }

    It 'fails closed (no crash) on an integer larger than Int64' {
        InModuleScope woscap {
            $ct = 'Use the Windows Registry Editor to navigate to the following key: HKLM\SOFTWARE\Policies\Microsoft\Edge  If the value for "Huge" is not set to "REG_QWORD = 99999999999999999999999", this is a finding.'
            ConvertTo-WoscapCheckDescriptor -Rule (New-Rule $ct) | Should -BeNullOrEmpty
        }
    }

    It 'returns $null when the rule states more than one registry value (ambiguous pairing)' {
        InModuleScope woscap {
            $ct = 'Use the Windows Registry Editor to navigate to the following key: HKLM\SOFTWARE\Policies\Microsoft\Edge  If the value for "A" is not set to "REG_DWORD = 1", this is a finding. If the value for "B" is not set to "REG_DWORD = 0", this is a finding.'
            ConvertTo-WoscapCheckDescriptor -Rule (New-Rule $ct) | Should -BeNullOrEmpty
        }
    }
}

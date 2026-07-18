BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    InModuleScope woscap {
        function script:New-Rule { param([string] $CheckText) [pscustomobject]@{ StigId = 'DTBC-0011'; CheckText = $CheckText } }
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'ConvertTo-WoscapChromePolicyDescriptor (chrome://policy -> registry)' {
    It 'maps a boolean "false" policy to REG_DWORD 0 under the Chrome policies key' {
        InModuleScope woscap {
            $ct = 'Universal method: 1. In the omnibox (address bar) type chrome://policy 2. If PasswordManagerEnabled is not displayed under the Policy Name column or it is not set to false under the Policy Value column, this is a finding.'
            $d = ConvertTo-WoscapChromePolicyDescriptor -Rule (New-Rule $ct)
            $d.Type     | Should -Be 'Registry'
            $d.Path     | Should -Be 'HKLM:\SOFTWARE\Policies\Google\Chrome'
            $d.Name     | Should -Be 'PasswordManagerEnabled'
            $d.Operator | Should -Be 'eq'
            $d.Expected | Should -Be 0
            $d.Expected | Should -BeOfType [int]
        }
    }

    It 'maps a boolean "true" policy to REG_DWORD 1' {
        InModuleScope woscap {
            $ct = 'If DefaultSearchProviderEnabled is not displayed under the Policy Name column or it is not set to true under the Policy Value column, this is a finding.'
            (ConvertTo-WoscapChromePolicyDescriptor -Rule (New-Rule $ct)).Expected | Should -Be 1
        }
    }

    It 'keeps an integer enum value' {
        InModuleScope woscap {
            $ct = "If the policy 'DeveloperToolsAvailability' is not shown or is not set to '2', this is a finding."
            $d = ConvertTo-WoscapChromePolicyDescriptor -Rule (New-Rule $ct)
            $d.Name     | Should -Be 'DeveloperToolsAvailability'
            $d.Expected | Should -Be 2
        }
    }

    It 'returns $null for a list policy (value is a wildcard/entry, stored under registry subkeys)' {
        InModuleScope woscap {
            $ct = 'If ExtensionInstallBlocklist is not displayed under the Policy Name column or it is not set to * under the Policy Value column, this is a finding.'
            ConvertTo-WoscapChromePolicyDescriptor -Rule (New-Rule $ct) | Should -BeNullOrEmpty
        }
    }

    It 'returns $null for a multi-value ("1 or 2") requirement' {
        InModuleScope woscap {
            $ct = 'If SafeBrowsingProtectionLevel is not displayed under the Policy Name column or it is not set to 1 or 2 under the Policy Value column, this is a finding.'
            ConvertTo-WoscapChromePolicyDescriptor -Rule (New-Rule $ct) | Should -BeNullOrEmpty
        }
    }

    It 'returns $null for an organization-specific string value' {
        InModuleScope woscap {
            $ct = 'If DefaultSearchProviderName is not set to an organization approved encrypted search provider, this is a finding.'
            ConvertTo-WoscapChromePolicyDescriptor -Rule (New-Rule $ct) | Should -BeNullOrEmpty
        }
    }

    It 'returns $null for a version cross-reference rule (no policy value stated)' {
        InModuleScope woscap {
            $ct = 'Universal method: 1. type chrome://settings/help 2. Cross-reference the build information with the Google Chrome site. If the installed version is unsupported, this is a finding.'
            ConvertTo-WoscapChromePolicyDescriptor -Rule (New-Rule $ct) | Should -BeNullOrEmpty
        }
    }

    It 'fails closed (no crash) on an integer larger than Int32 (not a REG_DWORD)' {
        InModuleScope woscap {
            $ct = 'If SomeTimeout is not displayed under the Policy Name column or it is not set to 9999999999 under the Policy Value column, this is a finding.'
            ConvertTo-WoscapChromePolicyDescriptor -Rule (New-Rule $ct) | Should -BeNullOrEmpty
        }
    }

    It 'extracts from the first clause when a rule states the same policy via both methods' {
        InModuleScope woscap {
            # Real Chrome rules give the chrome://policy method AND a Windows-registry method for the
            # SAME policy/value; the first clause is used and both agree.
            $ct = 'Universal method: If PasswordManagerEnabled is not displayed under the Policy Name column or it is not set to false under the Policy Value column, this is a finding. Windows method: Navigate to HKLM\Software\Policies\Google\Chrome\ If the PasswordManagerEnabled value name does not exist or its value data is not set to 0, this is a finding.'
            $d = ConvertTo-WoscapChromePolicyDescriptor -Rule (New-Rule $ct)
            $d.Name     | Should -Be 'PasswordManagerEnabled'
            $d.Expected | Should -Be 0
        }
    }
}

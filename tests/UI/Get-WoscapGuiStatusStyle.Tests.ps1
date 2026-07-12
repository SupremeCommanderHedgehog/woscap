BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Drawing
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapGuiStatusStyle' {
    It 'maps <Status> to the expected row colors' -ForEach @(
        @{ Status = 'Open';           Back = @(255,199,206); Fore = @(156,0,6)   }
        @{ Status = 'NotAFinding';    Back = @(198,239,206); Fore = @(0,97,0)    }
        @{ Status = 'Not_Reviewed';   Back = @(255,235,156); Fore = @(156,101,0) }
        @{ Status = 'Not_Applicable'; Back = @(217,217,217); Fore = @(89,89,89)  }
    ) {
        InModuleScope woscap -Parameters @{ Status = $Status; Back = $Back; Fore = $Fore } {
            param($Status, $Back, $Fore)
            $style = Get-WoscapGuiStatusStyle -Status $Status
            $style.BackColor.R | Should -Be $Back[0]
            $style.BackColor.G | Should -Be $Back[1]
            $style.BackColor.B | Should -Be $Back[2]
            $style.ForeColor.R | Should -Be $Fore[0]
            $style.ForeColor.G | Should -Be $Fore[1]
            $style.ForeColor.B | Should -Be $Fore[2]
        }
    }

    It 'returns $null for an unknown status so the row keeps default colors' {
        InModuleScope woscap {
            Get-WoscapGuiStatusStyle -Status 'Bogus' | Should -BeNullOrEmpty
        }
    }

    It 'returns $null for an empty status' {
        InModuleScope woscap {
            Get-WoscapGuiStatusStyle -Status '' | Should -BeNullOrEmpty
        }
    }
}

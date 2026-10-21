BeforeDiscovery {
    $script:equivCases = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; Name = 'CurrentBuild' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; Name = 'InstallDate' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; Name = 'InstallTime' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; Name = 'DigitalProductId' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog'; Name = 'ImagePath' }
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder'; Name = 'List' }
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; Name = 'WoscapNoSuchValue' }
        @{ Path = 'HKLM:\SOFTWARE\WoscapNoSuchKey'; Name = 'X' }
    )
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

# Get-RegValue is a thin wrapper over Get-RegValueEntry (one registry reader), so
# these mock the reader's key-open step (Get-Item) rather than Get-ItemProperty.
Describe 'Get-RegValue' {
    It 'returns the named value when present' {
        InModuleScope woscap {
            Mock Get-RegValueEntry { [pscustomobject]@{ Value = 1; Kind = 'DWord' } }
            Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' |
                Should -Be 1
        }
    }
    It 'returns $null when the key is genuinely missing (no throw)' {
        InModuleScope woscap {
            Mock Get-Item { throw [System.Management.Automation.ItemNotFoundException]::new('no key') }
            $v = Get-RegValue -Path 'HKLM:\Nope' -Name 'Missing'
            $v | Should -BeNullOrEmpty
            Test-WoscapUnreadable -Value $v | Should -BeFalse -Because 'absent is real evidence, not a failed read'
        }
    }
    It 'returns $null when the value name is genuinely missing' {
        InModuleScope woscap {
            Test-WoscapUnreadable -Value (Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'WoscapNoSuchValue') | Should -BeFalse
            Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'WoscapNoSuchValue' | Should -BeNullOrEmpty
        }
    }
    It 'returns the unreadable sentinel when the read fails for any other reason' {
        InModuleScope woscap {
            # A permission failure must not read as "absent", because
            # AbsentIsPass would score it compliant.
            Mock Get-Item { throw [System.Security.SecurityException]::new('access denied') }
            $v = Get-RegValue -Path 'HKLM:\SECURITY' -Name 'X'
            Test-WoscapUnreadable -Value $v | Should -BeTrue
            Get-WoscapUnreadableReason -Value $v | Should -Match 'access denied'
        }
    }
    It 'returns exactly (Get-RegValueEntry).Value for <Path>\<Name>' -ForEach $script:equivCases {
        InModuleScope woscap -Parameters @{ P = $Path; N = $Name } {
            param($P, $N)
            $entry = Get-RegValueEntry -Path $P -Name $N
            $value = Get-RegValue -Path $P -Name $N
            if ($null -eq $entry) { $value | Should -BeNullOrEmpty; return }
            $value.GetType() | Should -Be $entry.Value.GetType()
            , $value | Should -Be (, $entry.Value)
        }
    }
}

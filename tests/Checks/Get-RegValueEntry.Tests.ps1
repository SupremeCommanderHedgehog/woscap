# Reads only existing keys; never creates registry state (TestRegistry: writes to HKCU).
BeforeDiscovery {
    $script:ntKey  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $script:noNt   = -not (Test-Path -LiteralPath $script:ntKey)
    $script:noEvt  = -not (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog')
    $script:noSgo  = -not (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder')
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:ntKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    # CI runs on Windows Server, where an individual value may be missing.
    function Get-EntryOrSkip {
        param([string] $Path, [string] $Name, [switch] $ExactNameCase)
        $e = InModuleScope woscap -Parameters @{ P = $Path; N = $Name; X = [bool]$ExactNameCase } {
            param($P, $N, $X)
            Get-RegValueEntry -Path $P -Name $N -ExactNameCase:$X
        }
        $e
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-RegValueEntry' {
    Context 'value kinds' {
        It 'reads a REG_SZ as String' -Skip:$script:noNt {
            $e = Get-EntryOrSkip $script:ntKey 'CurrentBuild'
            if ($null -eq $e) { Set-ItResult -Skipped -Because 'CurrentBuild absent on this host'; return }
            $e.Kind | Should -Be 'String'
            $e.Value | Should -BeOfType [string]
        }
        It 'reads a REG_DWORD as DWord' -Skip:$script:noNt {
            $e = Get-EntryOrSkip $script:ntKey 'InstallDate'
            if ($null -eq $e) { Set-ItResult -Skipped -Because 'InstallDate absent on this host'; return }
            $e.Kind | Should -Be 'DWord'
            $e.Value | Should -BeOfType [int]
        }
        It 'reads a REG_QWORD as QWord' -Skip:$script:noNt {
            $e = Get-EntryOrSkip $script:ntKey 'InstallTime'
            if ($null -eq $e) { Set-ItResult -Skipped -Because 'InstallTime absent on this host'; return }
            $e.Kind | Should -Be 'QWord'
            $e.Value | Should -BeOfType [long]
        }
        It 'reads a REG_BINARY as Binary' -Skip:$script:noNt {
            $e = Get-EntryOrSkip $script:ntKey 'DigitalProductId'
            if ($null -eq $e) { Set-ItResult -Skipped -Because 'DigitalProductId absent on this host'; return }
            $e.Kind | Should -Be 'Binary'
            , $e.Value | Should -BeOfType [byte[]]
        }
        It 'reads a REG_EXPAND_SZ as ExpandString, expanded' -Skip:$script:noEvt {
            $e = Get-EntryOrSkip 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog' 'ImagePath'
            if ($null -eq $e) { Set-ItResult -Skipped -Because 'EventLog ImagePath absent on this host'; return }
            $e.Kind | Should -Be 'ExpandString'
            $e.Value | Should -Not -Match '%SystemRoot%'
        }
        It 'reads a REG_MULTI_SZ as MultiString, as a string array' -Skip:$script:noSgo {
            $e = Get-EntryOrSkip 'HKLM:\SYSTEM\CurrentControlSet\Control\ServiceGroupOrder' 'List'
            if ($null -eq $e) { Set-ItResult -Skipped -Because 'ServiceGroupOrder List absent on this host'; return }
            $e.Kind | Should -Be 'MultiString'
            , $e.Value | Should -BeOfType [string[]]
        }
    }

    Context 'absent' {
        It 'returns $null for a missing value' -Skip:$script:noNt {
            Get-EntryOrSkip $script:ntKey 'WoscapNoSuchValue' | Should -BeNullOrEmpty
        }
        It 'returns $null for a missing key' {
            Get-EntryOrSkip 'HKLM:\SOFTWARE\WoscapNoSuchKey\Sub' 'X' | Should -BeNullOrEmpty
        }
    }

    Context '-ExactNameCase' {
        It 'treats a wrong-case value name as absent' -Skip:$script:noNt {
            Get-EntryOrSkip $script:ntKey 'currentbuild' -ExactNameCase | Should -BeNullOrEmpty
        }
        It 'reads the value when the name case matches' -Skip:$script:noNt {
            $e = Get-EntryOrSkip $script:ntKey 'CurrentBuild' -ExactNameCase
            if ($null -eq $e) { Set-ItResult -Skipped -Because 'CurrentBuild absent on this host'; return }
            $e.Kind | Should -Be 'String'
        }
        It 'treats a wrong-case subkey segment as absent' -Skip:$script:noNt {
            Get-EntryOrSkip 'HKLM:\SOFTWARE\Microsoft\windows nt\CurrentVersion' 'CurrentBuild' -ExactNameCase |
                Should -BeNullOrEmpty
        }
        It 'matches any case without the switch' -Skip:$script:noNt {
            $e = Get-EntryOrSkip 'HKLM:\SOFTWARE\Microsoft\windows nt\CurrentVersion' 'currentbuild'
            if ($null -eq $e) { Set-ItResult -Skipped -Because 'CurrentBuild absent on this host'; return }
            $e.Kind | Should -Be 'String'
        }
    }

    Context 'unreadable' {
        It 'returns the unreadable sentinel when the key cannot be opened' {
            InModuleScope woscap {
                # A permission failure must not read as absent, or AbsentIsPass would pass it.
                Mock Get-Item { throw [System.Security.SecurityException]::new('access denied') }
                $v = Get-RegValueEntry -Path 'HKLM:\SECURITY\X' -Name 'Y'
                Test-WoscapUnreadable -Value $v | Should -BeTrue
                Get-WoscapUnreadableReason -Value $v | Should -Match 'access denied'
            }
        }
        It 'returns the unreadable sentinel when -ExactNameCase cannot enumerate' {
            InModuleScope woscap {
                Mock Get-Item { throw [System.Security.SecurityException]::new('access denied') }
                $v = Get-RegValueEntry -Path 'HKLM:\SECURITY\X' -Name 'Y' -ExactNameCase
                Test-WoscapUnreadable -Value $v | Should -BeTrue
            }
        }
    }
}

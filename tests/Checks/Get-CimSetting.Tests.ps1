BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-CimSetting' {
    BeforeEach { InModuleScope woscap { Clear-WoscapReadCache } }

    It 'returns the requested property from a single instance' {
        InModuleScope woscap {
            Mock Get-CimInstance { [pscustomobject]@{ VirtualizationBasedSecurityStatus = 2 } }
            Get-CimSetting -ClassName 'Win32_DeviceGuard' -Property 'VirtualizationBasedSecurityStatus' | Should -Be 2
        }
    }
    It 'returns an array property intact' {
        InModuleScope woscap {
            Mock Get-CimInstance { [pscustomobject]@{ SecurityServicesRunning = @(1,2) } }
            $v = Get-CimSetting -ClassName 'Win32_DeviceGuard' -Property 'SecurityServicesRunning'
            @($v).Count | Should -Be 2
        }
    }
    It 'collects the property across multiple instances' {
        InModuleScope woscap {
            Mock Get-CimInstance { @(
                [pscustomobject]@{ FileSystem = 'NTFS' }
                [pscustomobject]@{ FileSystem = 'FAT32' }
            )}
            $v = @(Get-CimSetting -ClassName 'Win32_Volume' -Property 'FileSystem')
            $v.Count | Should -Be 2
            $v       | Should -Contain 'FAT32'
        }
    }
    It 'returns the unreadable sentinel when the class cannot be queried' {
        InModuleScope woscap {
            # WMI throws identically for "class does not exist" and "access
            # denied", so both are treated as unreadable. Genuine hardware
            # absence is expressed through an applicability predicate instead.
            Mock Get-CimInstance { throw 'Invalid class' }
            Test-WoscapUnreadable -Value (Get-CimSetting -ClassName 'Nope' -Property 'X') | Should -BeTrue
        }
    }
    It 'reports unreadable when instances exist but none carries the property' {
        InModuleScope woscap {
            # A mistyped Property is a pack defect. Returned as $null it passed
            # the ne/notin/setequals family instead of surfacing.
            Mock Get-CimInstance { [pscustomobject]@{ A = 'a' } }
            $v = Get-CimSetting -ClassName 'C' -Property 'Missing'
            Test-WoscapUnreadable -Value $v | Should -BeTrue
            Get-WoscapUnreadableReason -Value $v | Should -Match 'Missing'
        }
    }
    It 'returns an empty set when the class is readable but has no instances' {
        InModuleScope woscap {
            # Real evidence: no antivirus registered, no non-system share.
            Mock Get-CimInstance { @() }
            $v = Get-CimSetting -ClassName 'AntiVirusProduct' -Property 'displayName'
            Test-WoscapUnreadable -Value $v | Should -BeFalse
            @($v).Count | Should -Be 0
        }
    }
    It 'fails an exists check when the class has no instances' {
        InModuleScope woscap {
            Mock Get-CimInstance { @() }
            $d = @{ Type='Cim'; Namespace='root\SecurityCenter2'; ClassName='AntiVirusProduct'; Property='displayName'; Operator='exists'; Expected=$true }
            (Test-Descriptor -Descriptor $d).Result | Should -Be 'Fail'
        }
    }
    It 'passes Namespace and Filter through' {
        InModuleScope woscap {
            Mock Get-CimInstance { [pscustomobject]@{ displayName = 'Defender' } } -ParameterFilter {
                $Namespace -eq 'root\SecurityCenter2' -and $ClassName -eq 'AntiVirusProduct'
            }
            Get-CimSetting -Namespace 'root\SecurityCenter2' -ClassName 'AntiVirusProduct' -Property 'displayName' | Should -Be 'Defender'
        }
    }
    It 'queries once for repeated reads of the same class and property' {
        InModuleScope woscap {
            $script:cimHits = 0
            Mock Get-CimInstance { $script:cimHits++; [pscustomobject]@{ P = 1 } }
            $null = Get-CimSetting -ClassName 'C' -Property 'P'
            $null = Get-CimSetting -ClassName 'C' -Property 'P'
            $script:cimHits | Should -Be 1
        }
    }
    It 'does not confuse two properties of the same class' {
        InModuleScope woscap {
            Mock Get-CimInstance { [pscustomobject]@{ A = 'a'; B = 'b' } }
            Get-CimSetting -ClassName 'C' -Property 'A' | Should -Be 'a'
            Get-CimSetting -ClassName 'C' -Property 'B' | Should -Be 'b'
        }
    }
    It 'reads one query for several properties of the same class' {
        InModuleScope woscap {
            $script:cimHits = 0
            Mock Get-CimInstance { $script:cimHits++; [pscustomobject]@{ A = 'a'; B = 'b' } }
            $null = Get-CimSetting -ClassName 'C' -Property 'A'
            $null = Get-CimSetting -ClassName 'C' -Property 'B'
            $script:cimHits | Should -Be 1
        }
    }
}

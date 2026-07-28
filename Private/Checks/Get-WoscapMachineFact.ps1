function Get-WoscapMachineFact {
    <#
    .SYNOPSIS
        One cached, machine-observable fact used to decide rule applicability.
    .DESCRIPTION
        Each fact is read at most once per scan.

        A read that fails returns the unreadable sentinel. It previously
        returned $false (or 0 for OsBuild), which was the opposite of
        conservative: Test-WoscapApplicability compared that against the gate
        and marked the rule Not Applicable, so on a non-elevated scan every
        TPM- or BitLocker-gated rule vanished from scoring entirely and the
        report asserted the host had no TPM. NA is worse than a false Fail
        because it removes the rule from the Open count altogether.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('DomainJoined','TpmPresent','CameraPresent','BluetoothPresent','HypervisorPresent','OsBuild','LocalAdminEnabled')]
        [string] $Fact
    )
    Get-WoscapCachedValue -Key "fact:$Fact" -Producer {
        try {
            switch ($Fact) {
                'DomainJoined' {
                    [bool](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).PartOfDomain
                }
                'HypervisorPresent' {
                    [bool](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).HypervisorPresent
                }
                'TpmPresent' {
                    $tpm = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop
                    $null -ne $tpm
                }
                'CameraPresent' {
                    $cam = @(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop |
                        Where-Object { $_.PNPClass -eq 'Camera' -or $_.PNPClass -eq 'Image' })
                    $cam.Count -gt 0
                }
                'BluetoothPresent' {
                    $bt = @(Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop |
                        Where-Object { $_.PNPClass -eq 'Bluetooth' })
                    $bt.Count -gt 0
                }
                'OsBuild' {
                    [int](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).BuildNumber
                }
                'LocalAdminEnabled' {
                    # WN11-SO-000280 is Not Applicable when no local
                    # administrator account is enabled.
                    $names = Get-LocalAccountSetting -Scope User -Property EnabledNames
                    if (Test-WoscapUnreadable -Value $names) { throw 'local accounts unreadable' }
                    $members = Get-LocalAccountSetting -Scope Group -Name 'Administrators' -Property Members
                    if (Test-WoscapUnreadable -Value $members) { throw 'Administrators group unreadable' }
                    $enabled = @($names)
                    $admins  = @($members)
                    @($enabled | Where-Object { $n = $_; @($admins | Where-Object { $_ -eq $n }).Count -gt 0 }).Count -gt 0
                }
            }
        } catch {
            New-WoscapUnreadable -Reason "cannot determine ${Fact}: $($_.Exception.Message)"
        }
    }
}

# Scriptblock escape hatch: rules whose check-content cannot be expressed as a
# declarative descriptor. Each returns one of Pass/Fail/NA/NotReviewed/Error.
#
# These use the same read-only helpers as the declarative types. A read that
# cannot be performed returns 'Error', never 'Pass'. The fail-closed invariant
# in tests/Checks/FailClosed.Tests.ps1 holds here by convention rather than by
# construction, because the engine cannot see inside a scriptblock - so every
# catch below returns Error and every "cannot determine" returns NotReviewed.
@{
    # WN11-00-000170 (CAT II) - SMBv1 client (mrxsmb10) must be disabled (Start = 4).
    'WN11-00-000170' = @{
        Type   = 'ScriptBlock'
        Script = {
            $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start'
            if (Test-WoscapUnreadable -Value $v) { 'Error' }
            elseif ($v -eq 4) { 'Pass' } else { 'Fail' }
        }
    }

    # WN11-00-000015 (CAT II) - firmware must run in UEFI mode, not Legacy BIOS.
    'WN11-00-000015' = @{
        Type   = 'ScriptBlock'
        Script = {
            try {
                # firmware_type is 'UEFI' or 'Legacy'. Where the variable is not
                # published, the presence of the SecureBoot state key is the
                # documented UEFI indicator (it does not exist on legacy BIOS).
                $fw = $env:firmware_type
                if (-not [string]::IsNullOrWhiteSpace($fw)) {
                    if ($fw -eq 'UEFI') { 'Pass' } else { 'Fail' }
                } elseif (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State') {
                    'Pass'
                } else {
                    'Fail'
                }
            } catch { 'Error' }
        }
    }

    # WN11-00-000030 (CAT I) - BitLocker on the OS volume and every fixed data
    # volume. ProtectionStatus 1 means protection is on.
    'WN11-00-000030' = @{
        Type   = 'ScriptBlock'
        Script = {
            try {
                $vols = @(Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' `
                    -ClassName 'Win32_EncryptableVolume' -ErrorAction Stop)
                # No volumes returned means the provider could not be read, not
                # that there is nothing to encrypt.
                if ($vols.Count -eq 0) { return 'Error' }
                $unprotected = @($vols | Where-Object { $_.ProtectionStatus -ne 1 })
                if ($unprotected.Count -eq 0) { 'Pass' } else { 'Fail' }
            } catch {
                # Requires elevation; an unreadable volume set is never a Pass.
                'Error'
            }
        }
    }

    # WN11-00-000035 (CAT II) - a deny-all, permit-by-exception allowlisting
    # program. AppLocker is the built-in one; a third-party product cannot be
    # detected, so the absence of AppLocker rules is a question, not a finding.
    'WN11-00-000035' = @{
        Type   = 'ScriptBlock'
        Script = {
            try {
                $configured = $false
                $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
                if (Test-Path -LiteralPath $base) {
                    foreach ($collection in @('Exe','Msi','Script','Appx','Dll')) {
                        $path = Join-Path $base $collection
                        if (-not (Test-Path -LiteralPath $path)) { continue }
                        if (@(Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue).Count -gt 0) {
                            $configured = $true
                            break
                        }
                    }
                }
                if ($configured) { 'Pass' } else { 'NotReviewed' }
            } catch { 'Error' }
        }
    }

    # WN11-00-000050 (CAT II) - every volume with a drive letter must be NTFS.
    # Recovery and EFI system partitions carry no letter and are out of scope.
    'WN11-00-000050' = @{
        Type   = 'ScriptBlock'
        Script = {
            try {
                $vols = @(Get-CimInstance -ClassName 'Win32_Volume' -ErrorAction Stop |
                    Where-Object { $_.DriveLetter -and $_.DriveType -eq 3 })
                if ($vols.Count -eq 0) { return 'Error' }
                $nonNtfs = @($vols | Where-Object { $_.FileSystem -ne 'NTFS' })
                if ($nonNtfs.Count -eq 0) { 'Pass' } else { 'Fail' }
            } catch { 'Error' }
        }
    }

    # WN11-00-000055 (CAT II) - no alternate operating system installed.
    'WN11-00-000055' = @{
        Type   = 'ScriptBlock'
        Script = {
            try {
                $os = @(Get-CimInstance -ClassName 'Win32_OperatingSystem' -ErrorAction Stop)
                if ($os.Count -eq 0) { 'Error' }
                elseif ($os.Count -eq 1) { 'Pass' }
                else { 'Fail' }
            } catch { 'Error' }
        }
    }

    # WN11-00-000125 (CAT II) - Copilot must be removed.
    'WN11-00-000125' = @{
        Type   = 'ScriptBlock'
        Script = {
            try {
                $pkgs = @(Get-AppxPackage -AllUsers -ErrorAction Stop |
                    Where-Object { $_.Name -like '*Copilot*' })
                if ($pkgs.Count -eq 0) { 'Pass' } else { 'Fail' }
            } catch {
                # Get-AppxPackage -AllUsers requires elevation.
                'Error'
            }
        }
    }

    # WN11-00-000190 (CAT III) - no orphaned SIDs on user rights. secedit
    # renders an unresolvable principal as a literal *S-1-... string.
    'WN11-00-000190' = @{
        Type   = 'ScriptBlock'
        Script = {
            try {
                $parsed = ConvertFrom-SecEditInf -InfText (Invoke-SecEditExport)
                if (-not $parsed.ContainsKey('Privilege Rights')) { return 'Error' }
                $orphans = New-Object System.Collections.Generic.List[string]
                foreach ($right in @($parsed['Privilege Rights'].Keys)) {
                    foreach ($principal in @($parsed['Privilege Rights'][$right])) {
                        $bare = ([string]$principal) -replace '^\*', ''
                        if ($bare -notmatch '^S-1-') { continue }
                        try {
                            $sid = New-Object System.Security.Principal.SecurityIdentifier($bare)
                            $null = $sid.Translate([System.Security.Principal.NTAccount])
                        } catch {
                            $orphans.Add(('{0}={1}' -f $right, $bare))
                        }
                    }
                }
                if ($orphans.Count -eq 0) { 'Pass' } else { 'Fail' }
            } catch { 'Error' }
        }
    }

    # WN11-00-000395 (CAT II) - no portproxy v4tov4 entries. This tests for the
    # KEY and its value names, which a declarative Registry descriptor cannot
    # express because that reads one named value.
    'WN11-00-000395' = @{
        Type   = 'ScriptBlock'
        Script = {
            try {
                $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp'
                if (-not (Test-Path -LiteralPath $key)) { return 'Pass' }
                $item = Get-Item -LiteralPath $key -ErrorAction Stop
                if (@($item.GetValueNames()).Count -eq 0) { 'Pass' } else { 'Fail' }
            } catch { 'Error' }
        }
    }

    # WN11-CC-000063 (CAT II) - the system must receive policy from Group Policy
    # or from a running MDM.
    'WN11-CC-000063' = @{
        Type   = 'ScriptBlock'
        Script = {
            try {
                $cs = Get-CimInstance -ClassName 'Win32_ComputerSystem' -ErrorAction Stop
                if ($cs.PartOfDomain) { return 'Pass' }
                $intune = Get-CimInstance -ClassName 'Win32_Service' `
                    -Filter "Name='IntuneManagementExtension'" -ErrorAction SilentlyContinue
                if ($null -ne $intune -and $intune.State -eq 'Running') { 'Pass' } else { 'Fail' }
            } catch { 'Error' }
        }
    }
}

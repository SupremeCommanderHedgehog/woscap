# Scriptblock escape hatch: rules whose check-content cannot be expressed as a
# declarative descriptor. Each returns one of Pass/Fail/NA/NotReviewed/Error.
#
# These use the same read-only helpers as the declarative types. A read that
# cannot be performed returns 'Error', never 'Pass'. The fail-closed invariant
# in tests/Checks/FailClosed.Tests.ps1 holds here by convention rather than by
# construction, because the engine cannot see inside a scriptblock - so every
# catch below returns Error and every "cannot determine" returns NotReviewed.
# Manual entries whose evidence needs a script also live here; evidence is
# reported, never judged.
@{
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

    # WN11-00-000400 (CAT II) - Wi-Fi Direct adapters. Hidden adapters are only
    # returned with -IncludeHidden, which a plain MSFT_NetAdapter query omits.
    # The check text calls any listed adapter a finding while the title and fix
    # accept a disabled one, so an all-disabled set is left to a reviewer.
    'WN11-00-000400' = @{
        Type   = 'ScriptBlock'
        Script = {
            try {
                $adapters = @(Get-NetAdapter -InterfaceDescription 'Microsoft Wi-Fi Direct*' -IncludeHidden -ErrorAction Stop)
                if ($adapters.Count -eq 0) { return 'Pass' }
                $active = @($adapters | Where-Object { [string]$_.Status -ne 'Disabled' })
                if ($active.Count -gt 0) { 'Fail' } else { 'NotReviewed' }
            } catch { 'Error' }
        }
    }

    # WN11-PK-000010 (CAT II) - an unexpired ECA Root CA in the Trusted Root
    # store, and (V2R11) no listed "*ECA*" certificate expired or not named
    # "ECA Root CA".
    'WN11-PK-000010' = @{
        Type   = 'ScriptBlock'
        Script = {
            $listed = @(Get-CertificateSetting -Store 'root' -Match @{ Subject = 'ECA' })
            $valid  = @(Get-CertificateSetting -Store 'root' -Match @{ Subject = 'ECA' } -RequireUnexpired)
            if ((Test-WoscapUnreadable -Value $listed) -or (Test-WoscapUnreadable -Value $valid)) { return 'Error' }
            $misnamed = @($listed | Where-Object { $_ -notmatch 'CN=ECA Root CA' })
            if ($valid.Count -eq 0 -or $valid.Count -ne $listed.Count -or $misnamed.Count -gt 0) { 'Fail' } else { 'Pass' }
        }
    }

    # WN11-PK-000015 (CAT II) - an unexpired DoD Interoperability cross-cert in
    # the Untrusted store, and (V2R11) none of the listed ones expired.
    'WN11-PK-000015' = @{
        Type   = 'ScriptBlock'
        Script = {
            $match  = @{ Issuer = 'DoD Interoperability'; Subject = 'DoD' }
            $listed = @(Get-CertificateSetting -Store 'disallowed' -Match $match)
            $valid  = @(Get-CertificateSetting -Store 'disallowed' -Match $match -RequireUnexpired)
            if ((Test-WoscapUnreadable -Value $listed) -or (Test-WoscapUnreadable -Value $valid)) { return 'Error' }
            if ($valid.Count -eq 0 -or $valid.Count -ne $listed.Count) { 'Fail' } else { 'Pass' }
        }
    }

    # WN11-PK-000020 (CAT II) - an unexpired US DoD CCEB Interoperability
    # cross-cert in the Untrusted store, and (V2R11) none of the listed ones
    # expired. The text's "DoD Interoperability Root CA" name test is a copy of
    # PK-000015 that no CCEB certificate can meet, so the filter's issuer is used.
    'WN11-PK-000020' = @{
        Type   = 'ScriptBlock'
        Script = {
            $match  = @{ Issuer = 'CCEB Interoperability' }
            $listed = @(Get-CertificateSetting -Store 'disallowed' -Match $match)
            $valid  = @(Get-CertificateSetting -Store 'disallowed' -Match $match -RequireUnexpired)
            if ((Test-WoscapUnreadable -Value $listed) -or (Test-WoscapUnreadable -Value $valid)) { return 'Error' }
            if ($valid.Count -eq 0 -or $valid.Count -ne $listed.Count) { 'Fail' } else { 'Pass' }
        }
    }

    # WN11-00-000085 (CAT II) - standard local accounts on a domain member. V2R11
    # counts disabled accounts too and allows "local administrator account(s)",
    # which only a reviewer can identify; every local account is the evidence.
    'WN11-00-000085' = @{
        Applicability = @{ DomainJoined = $true }
        Type     = 'Manual'
        Question = 'Do any local user accounts exist, enabled or disabled, other than the built-in Guest (RID 501), DefaultAccount (RID 503), defaultuser0, WDAGUtilityAccount (RID 504) and the local administrator account(s)? Any other local user account is a finding.'
        Evidence = @{
            Type   = 'ScriptBlock'
            Script = {
                try {
                    $users = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
                        $rid = ([string]$_.SID.Value -split '-')[-1]
                        $state = if ($_.Enabled) { 'enabled' } else { 'disabled' }
                        '{0} (RID {1}, {2})' -f $_.Name, $rid, $state
                    })
                    if ($users.Count -eq 0) { 'no local user accounts' } else { $users -join '; ' }
                } catch { "local accounts unreadable: $($_.Exception.Message)" }
            }
        }
    }

    # WN11-SO-000280 (CAT II) - local administrator password age and LAPS. The
    # admin account need not be named Administrator and LAPS state lives in
    # policy, CSP or Config keys plus an event log, so a reviewer decides.
    'WN11-SO-000280' = @{
        Applicability = @{ LocalAdminEnabled = $true }
        Type     = 'Manual'
        Question = 'For every enabled local administrator account, is PasswordLastSet within the last 180 days? Is Windows LAPS in effect with Password Complexity 4 (large + small letters + numbers + special), Password Length 14 or more and Password Age 180 days or less, and does the LAPS Operational log (Applications and Services Logs > Microsoft > Windows > LAPS > Operational) show policy processing completing? An enabled built-in account not managed by LAPS, or an alternative process, must be documented with the ISSM/ISSO.'
        Evidence = @{
            Type   = 'ScriptBlock'
            Script = {
                $lines = New-Object System.Collections.Generic.List[string]
                try {
                    $adminSids = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [string]$_.SID.Value })
                    $admins = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -and $adminSids -contains [string]$_.SID.Value })
                    if ($admins.Count -eq 0) { $lines.Add('enabled local administrators: none') }
                    foreach ($a in $admins) {
                        $rid = ([string]$a.SID.Value -split '-')[-1]
                        $age = if ($null -eq $a.PasswordLastSet) { 'never set' } else { '{0} days old' -f [int]((Get-Date) - $a.PasswordLastSet).TotalDays }
                        $lines.Add(('{0} (RID {1}, password {2})' -f $a.Name, $rid, $age))
                    }
                } catch { $lines.Add("local administrators unreadable: $($_.Exception.Message)") }
                foreach ($path in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS',
                                    'HKLM:\SOFTWARE\Microsoft\Policies\LAPS',
                                    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config')) {
                    $vals = foreach ($n in @('PasswordComplexity','PasswordLength','PasswordAgeDays')) {
                        $v = Get-RegValue -Path $path -Name $n
                        if (Test-WoscapUnreadable -Value $v) { "$n=unreadable" }
                        elseif ($null -ne $v) { "$n=$v" }
                    }
                    $vals = @($vals | Where-Object { $_ })
                    if ($vals.Count -eq 0) { $lines.Add("${path}: not set") } else { $lines.Add("${path}: $($vals -join ', ')") }
                }
                $lines -join '; '
            }
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

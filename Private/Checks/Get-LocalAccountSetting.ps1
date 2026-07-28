function Get-WoscapAdsiObject {
    <#
    .SYNOPSIS
        Bind an ADSI path. Split out purely so the bind can be mocked - the
        [ADSI] type accelerator cannot be, which previously left the swallowed
        failure in the callers below untestable.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)
    [ADSI]$Path
}

function Get-WoscapLocalUserRaw {
    <#
    .SYNOPSIS
        Normalized local user records read through the ADSI WinNT provider.
    .DESCRIPTION
        WinNT rather than Get-LocalUser: it is the method the STIG check text
        itself prescribes, it needs no LocalAccounts module, and it does not
        fail on domain principals nested in local groups.

        UserFlags bit 0x0002 is ACCOUNTDISABLE and 0x10000 is
        DONT_EXPIRE_PASSWD. An account that has never logged on reports
        LastLogonDays as [int]::MaxValue so it sorts as maximally stale.
    #>
    [CmdletBinding()]
    param()
    $root = Get-WoscapAdsiObject -Path "WinNT://$env:COMPUTERNAME"
    foreach ($child in $root.Children) {
        if ($child.SchemaClassName -ne 'user') { continue }
        $flags      = [int]($child.Properties['UserFlags'].Value)
        $ageSeconds = [int]($child.Properties['PasswordAge'].Value)
        $lastLogin  = $child.Properties['LastLogin'].Value
        $lastLogonDays = if ($null -eq $lastLogin) {
            [int]::MaxValue
        } else {
            [int]((Get-Date) - [datetime]$lastLogin).TotalDays
        }
        [pscustomobject]@{
            Name            = [string]$child.Properties['Name'].Value
            Enabled         = (($flags -band 0x0002) -eq 0)
            PasswordExpires = (($flags -band 0x10000) -eq 0)
            PasswordAgeDays = [int]($ageSeconds / 86400)
            LastLogonDays   = $lastLogonDays
        }
    }
}

function Get-WoscapLocalGroupMemberRaw {
    <#
    .SYNOPSIS
        Member names of a local group, read through the ADSI WinNT provider.
    .DESCRIPTION
        An unreadable group returns the unreadable sentinel, NOT an empty set.
        Empty means "the group has no members", which subsetof and setequals
        treat as compliant - so swallowing an access-denied or unresolved-name
        failure into @() reported Pass on a group that was never read.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name)
    try {
        $group = Get-WoscapAdsiObject -Path "WinNT://$env:COMPUTERNAME/$Name,group"
        @($group.Invoke('Members') | ForEach-Object { ([ADSI]$_).InvokeGet('Name') })
    } catch {
        New-WoscapUnreadable -Reason "cannot read local group '${Name}': $($_.Exception.Message)"
    }
}

function Get-LocalAccountSetting {
    <#
    .SYNOPSIS
        One projection over the local users or a local group.
    .DESCRIPTION
        Projections:
          User  / EnabledNames      - names of enabled accounts
          User  / NonExpiringNames  - enabled accounts whose password never expires
          User  / StaleNames        - enabled accounts idle beyond -ThresholdDays
          User  / PasswordAgeDays   - password age of -Name, or $null if unknown
          Group / Members           - member names of -Name

        Set projections are emitted enumerated; callers wrap in @().
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('User','Group')] [string] $Scope,
        [Parameter(Mandatory)] [ValidateSet('EnabledNames','NonExpiringNames','StaleNames','PasswordAgeDays','Members')]
        [string] $Property,
        [string] $Name,
        [int] $ThresholdDays = 35
    )
    # ValidateSet constrains Scope and Property independently but not their
    # combination, so 'User'+'Members' (the natural typo for 'Group') used to
    # reach the switch default, return $null, and score Pass under subsetof.
    # Reject the mismatch as a defect instead of answering it.
    $validCombinations = @{
        'User'  = @('EnabledNames','NonExpiringNames','StaleNames','PasswordAgeDays')
        'Group' = @('Members')
    }
    if ($validCombinations[$Scope] -notcontains $Property) {
        return (New-WoscapUnreadable -Reason "LocalAccount Scope '$Scope' does not support Property '$Property'")
    }

    if ($Scope -eq 'Group') {
        # -Name is not Mandatory on this function, so a Group descriptor that
        # omits it would otherwise reach the raw reader and fail parameter
        # binding. Report it as unreadable rather than as an empty membership,
        # which subsetof would score compliant.
        if ([string]::IsNullOrWhiteSpace($Name)) {
            return (New-WoscapUnreadable -Reason 'local group descriptor supplied no Name')
        }
        return Get-WoscapLocalGroupMemberRaw -Name $Name
    }

    $users = Get-WoscapCachedValue -Key 'localaccount:users' -Producer {
        try   { ,@(Get-WoscapLocalUserRaw) }
        catch { New-WoscapUnreadable -Reason "cannot enumerate local accounts: $($_.Exception.Message)" }
    }
    # NOT ,@(): an empty account list is compliant under setequals @(), so a
    # failed enumeration must not look like "no offending accounts".
    if (Test-WoscapUnreadable -Value $users) { return $users }

    $enabled = @(@($users) | Where-Object { $_.Enabled })

    switch ($Property) {
        'EnabledNames'     { $enabled | ForEach-Object { $_.Name } }
        'NonExpiringNames' { $enabled | Where-Object { -not $_.PasswordExpires } | ForEach-Object { $_.Name } }
        'StaleNames'       { $enabled | Where-Object { $_.LastLogonDays -gt $ThresholdDays } | ForEach-Object { $_.Name } }
        'PasswordAgeDays'  {
            $hit = @(@($users) | Where-Object { $_.Name -eq $Name })
            if ($hit.Count -eq 0) { $null } else { $hit[0].PasswordAgeDays }
        }
        default { $null }
    }
}

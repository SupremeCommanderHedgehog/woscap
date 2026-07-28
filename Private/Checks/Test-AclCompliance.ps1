function Test-AclCompliance {
    <#
    .SYNOPSIS
        Decide whether a path's ACL keeps non-privileged principals out.
    .DESCRIPTION
        Every DISA ACL rule this module implements has the same shape: no
        principal outside an allowed set may hold more than a permitted level
        of access. AllowedPrincipals may hold anything; anyone else may hold
        only rights named in MaxRights (empty MaxRights means no access at all).

        Deny aces are ignored - they only ever restrict.

        An unreadable path is reported non-compliant, never compliant. Most of
        these reads need elevation, and a silent pass on a permission failure
        is the worst outcome this check can produce.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $AllowedPrincipals,
        [AllowEmptyCollection()] [string[]] $MaxRights = @()
    )
    # HKLM: / HKCU: / HKCR: style paths read through the registry provider;
    # everything else is a filesystem path.
    $aces = if ($Path -match '^HK[A-Z]{2}:') {
        Get-RegistryAclSetting -Path $Path
    } else {
        Get-AclSetting -Path $Path
    }
    if ($null -eq $aces) {
        return [pscustomobject]@{ Compliant = $false; Offenders = "unreadable: $Path" }
    }

    # Compare principals by SID, not by display name. IdentityReference
    # stringifies to the LOCALIZED name ('VORDEFINIERT\Administratoren' on a
    # German host), so name matching made every Allow ACE an offender and every
    # Acl rule Open on any non-English install. Names are kept as a fallback for
    # principals that cannot be resolved on this machine.
    $allowedNames = @($AllowedPrincipals | ForEach-Object { $_.ToLowerInvariant() })
    $allowedSids  = @($AllowedPrincipals | ForEach-Object { Resolve-PrincipalSid -Name $_ } |
                      Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    $permitted    = @($MaxRights | ForEach-Object { $_.ToLowerInvariant() })

    $offenders = foreach ($ace in @($aces)) {
        if ($ace.Type -ne 'Allow') { continue }

        $identity = [string]$ace.Identity
        if ($allowedNames -contains $identity.ToLowerInvariant()) { continue }
        $aceSid = Resolve-PrincipalSid -Name $identity
        if ($aceSid -and $allowedSids -contains $aceSid.ToLowerInvariant()) { continue }

        $rights = @(ConvertTo-WoscapRightsToken -Rights ([string]$ace.Rights))
        $excess = @($rights | Where-Object { $permitted -notcontains $_.ToLowerInvariant() })
        if ($excess.Count -gt 0) { "$identity=$($ace.Rights)" }
    }
    $offenders = @($offenders | Where-Object { $null -ne $_ })

    [pscustomobject]@{
        Compliant = ($offenders.Count -eq 0)
        Offenders = if ($offenders.Count -eq 0) { '' } else { $offenders -join '; ' }
    }
}

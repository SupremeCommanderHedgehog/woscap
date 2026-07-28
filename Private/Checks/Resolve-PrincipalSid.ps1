function ConvertTo-WoscapNtAccountSid {
    <#
    .SYNOPSIS
        Translate an account name to a SID via NTAccount. Returns $null when
        the name cannot be translated.
    .DESCRIPTION
        Split out from Resolve-PrincipalSid so the fallback can be mocked away
        in tests. Translation is locale-dependent and unavailable off-domain,
        which is exactly why the well-known map takes precedence over it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name)
    try {
        $account = New-Object System.Security.Principal.NTAccount($Name)
        $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        $null
    }
}

function Resolve-PrincipalSid {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name)

    # Well-known principals used by DISA user-rights rules. Static map avoids
    # locale/translation issues; falls back to NTAccount translation otherwise.
    $wellKnown = @{
        'Administrators'                      = 'S-1-5-32-544'
        'Users'                               = 'S-1-5-32-545'
        'Guests'                              = 'S-1-5-32-546'
        'LOCAL SERVICE'                       = 'S-1-5-19'
        'NETWORK SERVICE'                     = 'S-1-5-20'
        'SERVICE'                             = 'S-1-5-6'
        'Everyone'                            = 'S-1-1-0'
        'Remote Desktop Users'                = 'S-1-5-32-555'
        'Backup Operators'                    = 'S-1-5-32-551'
        'Hyper-V Administrators'              = 'S-1-5-32-578'
        'Local account'                       = 'S-1-5-113'
        'NT VIRTUAL MACHINE\Virtual Machines' = 'S-1-5-83-0'
    }
    $key = $Name.Trim()
    if ($wellKnown.ContainsKey($key)) { return $wellKnown[$key] }

    ConvertTo-WoscapNtAccountSid -Name $key
}

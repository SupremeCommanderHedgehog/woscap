function Resolve-PrincipalSid {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name)

    # Well-known principals used by DISA user-rights rules. Static map avoids
    # locale/translation issues; falls back to NTAccount translation otherwise.
    $wellKnown = @{
        'Administrators'  = 'S-1-5-32-544'
        'Users'           = 'S-1-5-32-545'
        'Guests'          = 'S-1-5-32-546'
        'LOCAL SERVICE'   = 'S-1-5-19'
        'NETWORK SERVICE' = 'S-1-5-20'
        'SERVICE'         = 'S-1-5-6'
        'Everyone'        = 'S-1-1-0'
    }
    $key = $Name.Trim()
    if ($wellKnown.ContainsKey($key)) { return $wellKnown[$key] }

    try {
        $account = New-Object System.Security.Principal.NTAccount($key)
        $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        $null
    }
}

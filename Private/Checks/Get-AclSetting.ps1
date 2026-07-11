function Get-AclSetting {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)
    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
    } catch {
        return $null
    }
    foreach ($ace in $acl.Access) {
        [pscustomobject]@{
            Identity = [string]$ace.IdentityReference
            Rights   = [string]$ace.FileSystemRights
            Type     = [string]$ace.AccessControlType
        }
    }
}

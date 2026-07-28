function Get-RegistryAclSetting {
    <#
    .SYNOPSIS
        ACEs on a registry key, in the same shape Get-AclSetting returns for
        filesystem paths. Returns $null when the key cannot be read.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)
    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
    } catch {
        return $null
    }
    $entries = foreach ($ace in $acl.Access) {
        [pscustomobject]@{
            Identity = [string]$ace.IdentityReference
            Rights   = [string]$ace.RegistryRights
            Type     = [string]$ace.AccessControlType
        }
    }
    # Protected array, matching Get-AclSetting: an empty ACL must stay
    # distinguishable from an unreadable key.
    Write-Output -NoEnumerate @($entries | Where-Object { $null -ne $_ })
}

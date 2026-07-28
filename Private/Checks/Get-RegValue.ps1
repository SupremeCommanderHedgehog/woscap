function Get-RegValue {
    <#
    .SYNOPSIS
        One registry value, or $null when it is genuinely absent.
    .DESCRIPTION
        Distinguishes "absent" from "could not read". A missing key or missing
        value name is a legitimate absent reading and returns $null, which
        AbsentIsPass may treat as the compliant default. Any other failure -
        notably a permission error - returns the unreadable sentinel, because
        scoring an unreadable key as the compliant default is a false Pass.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name
    )
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        $item.$Name
    } catch {
        $notFound = @(
            'System.Management.Automation.ItemNotFoundException'
            'System.Management.Automation.PSArgumentException'
        )
        $type = if ($null -ne $_.Exception) { $_.Exception.GetType().FullName } else { '' }
        if ($notFound -contains $type) {
            $null
        } else {
            New-WoscapUnreadable -Reason "cannot read ${Path}\${Name}: $($_.Exception.Message)"
        }
    }
}

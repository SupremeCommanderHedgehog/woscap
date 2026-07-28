function Test-PathPresence {
    <#
    .SYNOPSIS
        Whether a filesystem path exists. Environment variables are expanded.
    .DESCRIPTION
        A failed test returns the unreadable sentinel rather than $false. These
        rules are worded "this binary must not exist" (Operator='eq';
        Expected=$false), so reporting absent on a failed test would pass a
        machine whose filesystem was never examined.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)
    try {
        [bool](Test-Path -Path ([System.Environment]::ExpandEnvironmentVariables($Path)) -ErrorAction Stop)
    } catch {
        New-WoscapUnreadable -Reason "cannot test path '${Path}': $($_.Exception.Message)"
    }
}

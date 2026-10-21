function Get-RegValue {
    <#
    .SYNOPSIS
        One registry value, or $null when it is genuinely absent.
    .DESCRIPTION
        A thin wrapper over Get-RegValueEntry that drops the kind, so woscap
        has one registry reader with one set of path and error rules. It
        returns exactly (Get-RegValueEntry -Path -Name).Value: Path is literal
        (no wildcards), a REG_MULTI_SZ or REG_BINARY comes back as one array,
        and REG_EXPAND_SZ is expanded.

        Distinguishes "absent" from "could not read". A missing key or missing
        value name is a legitimate absent reading and returns $null, which
        AbsentIsPass may treat as the compliant default. Any other failure -
        notably a permission error - returns the unreadable sentinel, because
        scoring an unreadable key as the compliant default is a false Pass.

        Use it only where the kind does not matter, such as evidence that is
        reported and never judged. A judged check needs Get-RegValueEntry.
    .PARAMETER Path
        Registry key path, e.g. 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'.
    .PARAMETER Name
        The value name under Path.
    .EXAMPLE
        Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuild'
        Returns the build number string, e.g. '26100'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name
    )
    $entry = Get-RegValueEntry -Path $Path -Name $Name
    if ($null -eq $entry) { return $null }
    if (Test-WoscapUnreadable -Value $entry) { return $entry }
    # The unary comma keeps an array value as one array rather than unrolling it.
    , $entry.Value
}

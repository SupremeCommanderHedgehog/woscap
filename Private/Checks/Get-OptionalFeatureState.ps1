function Get-OptionalFeatureState {
    <#
    .SYNOPSIS
        Install state of a Windows optional feature: Enabled, Disabled, Absent,
        or Unknown.
    .DESCRIPTION
        Reads Win32_OptionalFeature rather than Get-WindowsOptionalFeature: a
        plain CIM read, no DISM module, no elevation. InstallState 1 is
        Enabled, 2 is Disabled, 3 is Absent.

        FeatureName may contain wildcards, because WN11-00-000155 covers both
        MicrosoftWindowsPowerShellV2 and MicrosoftWindowsPowerShellV2Root. When
        several features match, Enabled wins - the STIG treats either being
        enabled as a finding.

        An unreadable class returns the unreadable sentinel, NOT a placeholder
        string. 'Unknown' looked safe but silently passed the documented idiom
        for these rules - Operator='notin'; Expected=@('Enabled') - because
        'Unknown' is indeed not 'Enabled'. That scored an unread machine as
        compliant.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $FeatureName)

    $features = Get-WoscapCachedValue -Key 'cim:optionalfeatures' -Producer {
        try   { ,@(Get-CimInstance -ClassName Win32_OptionalFeature -ErrorAction Stop) }
        catch { New-WoscapUnreadable -Reason "cannot enumerate Win32_OptionalFeature: $($_.Exception.Message)" }
    }
    if (Test-WoscapUnreadable -Value $features) { return $features }
    if ($null -eq $features) {
        return (New-WoscapUnreadable -Reason 'Win32_OptionalFeature returned no data')
    }

    $matched = @(@($features) | Where-Object { $_.Name -like $FeatureName })
    if ($matched.Count -eq 0) { return 'Absent' }
    if (@($matched | Where-Object { $_.InstallState -eq 1 }).Count -gt 0) { return 'Enabled' }
    if (@($matched | Where-Object { $_.InstallState -eq 2 }).Count -gt 0) { return 'Disabled' }
    'Absent'
}

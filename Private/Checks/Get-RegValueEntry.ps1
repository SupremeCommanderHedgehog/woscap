function Get-RegValueEntry {
    <#
    .SYNOPSIS
        One registry value together with its stored kind, or $null when it is
        genuinely absent.
    .DESCRIPTION
        Returns [pscustomobject]@{ Value; Kind }. Kind is the
        Microsoft.Win32.RegistryValueKind name: String, ExpandString,
        MultiString, DWord, QWord, Binary, None or Unknown. Value is what
        RegistryKey.GetValue returns, so REG_EXPAND_SZ comes back expanded,
        exactly as Get-ItemProperty (and Get-RegValue) reads it.

        A missing key or value name returns $null, which AbsentIsPass may treat
        as the compliant default. Any other failure - notably a permission
        error - returns the unreadable sentinel (New-WoscapUnreadable), because
        scoring an unreadable key as absent is a false Pass.

        Registry names are case-insensitive to Windows, but some products
        (Firefox) look values up case-sensitively. -ExactNameCase makes the
        value read as absent unless the value name and every subkey segment
        below the hive root match the stored case exactly. A failure to
        enumerate subkeys or value names returns the unreadable sentinel.
    .PARAMETER Path
        Registry key path, e.g. 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox' or
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\...'.
    .PARAMETER Name
        The value name under Path.
    .PARAMETER ExactNameCase
        Require the stored case of the value name and of each subkey segment
        below the hive root to match Path and Name exactly.
    .EXAMPLE
        Get-RegValueEntry -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuild'
        Returns @{ Value = '26100'; Kind = 'String' } on a build-26100 host.
    .EXAMPLE
        Get-RegValueEntry -Path 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox' -Name 'DisableTelemetry' -ExactNameCase
        Returns $null if the value is stored as 'disabletelemetry'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [switch] $ExactNameCase
    )
    $opened = New-Object System.Collections.Generic.List[object]
    try {
        if ($ExactNameCase) {
            # RegistryKey.Name echoes the caller's case, so the stored case is
            # only visible by enumerating each parent.
            $m = [regex]::Match($Path, '^(?<root>(?:(?:Microsoft\.PowerShell\.Core\\)?Registry::)?[^\\]+)(?:\\(?<rest>.*))?$')
            $key = Get-Item -LiteralPath ($m.Groups['root'].Value + '\') -ErrorAction Stop
            foreach ($segment in @($m.Groups['rest'].Value -split '\\' | Where-Object { $_ })) {
                if (-not (@($key.GetSubKeyNames()) -ccontains $segment)) { return $null }
                $key = $key.OpenSubKey($segment)
                if ($null -eq $key) { return $null }
                $opened.Add($key)
            }
            if (-not (@($key.GetValueNames()) -ccontains $Name)) { return $null }
        } else {
            $key = Get-Item -LiteralPath $Path -ErrorAction Stop
            if (-not (@($key.GetValueNames()) -contains $Name)) { return $null }
        }
        [pscustomobject]@{
            Value = $key.GetValue($Name)
            Kind  = $key.GetValueKind($Name).ToString()
        }
    } catch {
        $type = if ($null -ne $_.Exception) { $_.Exception.GetType().FullName } else { '' }
        if ($type -eq 'System.Management.Automation.ItemNotFoundException') {
            $null
        } else {
            New-WoscapUnreadable -Reason "cannot read ${Path}\${Name}: $($_.Exception.Message)"
        }
    } finally {
        foreach ($k in $opened) { $k.Close() }
    }
}

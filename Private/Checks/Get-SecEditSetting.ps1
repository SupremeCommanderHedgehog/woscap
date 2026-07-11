function Get-SecEditSetting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [string] $Section = 'System Access'
    )
    $parsed = ConvertFrom-SecEditInf -InfText (Invoke-SecEditExport)
    if ($parsed.ContainsKey($Section) -and $parsed[$Section].ContainsKey($Name)) {
        $parsed[$Section][$Name]
    } else {
        $null
    }
}

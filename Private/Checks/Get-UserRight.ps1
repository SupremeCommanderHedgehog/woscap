function Get-UserRight {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Privilege)
    $parsed = ConvertFrom-SecEditInf -InfText (Invoke-SecEditExport)
    if ($parsed.ContainsKey('Privilege Rights') -and $parsed['Privilege Rights'].ContainsKey($Privilege)) {
        Write-Output -NoEnumerate @($parsed['Privilege Rights'][$Privilege])
    } else {
        Write-Output -NoEnumerate @()
    }
}

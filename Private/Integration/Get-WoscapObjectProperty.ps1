function Get-WoscapObjectProperty {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowNull()] $InputObject, [Parameter(Mandatory)][string] $Name, $Default = $null)
    if ($null -eq $InputObject) { return $Default }
    if ($InputObject -is [hashtable]) {
        if ($InputObject.ContainsKey($Name)) { return $InputObject[$Name] } else { return $Default }
    }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($p) { return $p.Value } else { return $Default }
}

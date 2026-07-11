function Get-AuditPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Subcategory)
    $parsed = ConvertFrom-AuditPolCsv -CsvText (Invoke-AuditPol)
    if ($parsed.ContainsKey($Subcategory)) { @($parsed[$Subcategory]) } else { $null }
}

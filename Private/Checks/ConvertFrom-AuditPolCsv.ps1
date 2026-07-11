function ConvertFrom-AuditPolCsv {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $CsvText)

    $result = @{}
    foreach ($row in ($CsvText | ConvertFrom-Csv)) {
        $sub = $row.'Subcategory'
        if (-not $sub) { continue }
        $setting = $row.'Inclusion Setting'
        if ([string]::IsNullOrWhiteSpace($setting) -or $setting -eq 'No Auditing') {
            $result[$sub] = @()
        } else {
            $result[$sub] = @($setting -split '\s+and\s+')
        }
    }
    $result
}

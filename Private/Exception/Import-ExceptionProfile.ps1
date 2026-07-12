function Import-ExceptionProfile {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string[]] $Path)

    $merged = @{}
    foreach ($file in $Path) {
        if (-not (Test-Path -LiteralPath $file)) {
            throw "Exception profile not found: $file"
        }
        $data = Import-PowerShellDataFile -LiteralPath $file
        foreach ($key in $data.Keys) { $merged[$key] = $data[$key] }
    }
    $merged
}

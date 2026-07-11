function Import-ContentPack {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)

    $pack = @{}

    $psd1 = Join-Path $Path 'checks.psd1'
    if (Test-Path -LiteralPath $psd1) {
        $data = Import-PowerShellDataFile -LiteralPath $psd1
        foreach ($key in $data.Keys) { $pack[$key] = $data[$key] }
    }

    $overrides = Join-Path $Path 'checks.overrides.ps1'
    if (Test-Path -LiteralPath $overrides) {
        $sbMap = & $overrides
        if ($sbMap -is [hashtable]) {
            foreach ($key in $sbMap.Keys) { $pack[$key] = $sbMap[$key] }
        }
    }

    $pack
}

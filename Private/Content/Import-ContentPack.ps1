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

    # Validate structure at load time. Without this the schema validator was
    # dead code, and a descriptor with a dropped or misspelled Operator reached
    # the evaluator to be scored rather than reported as a pack defect. Warn
    # rather than throw so one bad entry cannot block an entire scan; the
    # offending rule still surfaces as Error when evaluated.
    foreach ($key in @($pack.Keys)) {
        $descriptor = $pack[$key]
        if ($descriptor -isnot [hashtable]) {
            Write-Warning "woscap: content entry '$key' is not a hashtable; it will not evaluate."
            continue
        }
        $problems = @(Test-WoscapDescriptorSchema -Descriptor $descriptor -Context $key)
        foreach ($problem in $problems) {
            Write-Warning "woscap: content pack defect - $problem"
        }
    }

    $pack
}

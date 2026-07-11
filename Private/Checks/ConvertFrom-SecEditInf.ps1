function ConvertFrom-SecEditInf {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $InfText)

    $result = @{}
    $section = $null
    foreach ($raw in ($InfText -split "`r?`n")) {
        $line = $raw.Trim()
        if (-not $line) { continue }
        if ($line -match '^\[(.+)\]$') {
            $section = $matches[1]
            $result[$section] = @{}
            continue
        }
        if ($null -ne $section -and $line -match '^(.*?)\s*=\s*(.*)$') {
            $key = $matches[1].Trim()
            $val = $matches[2].Trim()
            if ($section -eq 'Privilege Rights') {
                $result[$section][$key] = @($val -split '\s*,\s*')
            } else {
                $result[$section][$key] = $val
            }
        }
    }
    $result
}

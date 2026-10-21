function Test-WoscapPluginConfigSchema {
    # Returns error strings for the manifest's ConfigOptions; empty means valid.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Manifest)

    $errors = New-Object System.Collections.Generic.List[string]
    if (-not $Manifest.ContainsKey('ConfigOptions') -or $null -eq $Manifest['ConfigOptions']) { return @() }

    $types = @('Text', 'Number', 'Bool', 'Credential', 'Secret', 'List', 'Table', 'Path')
    $caps  = @(if ($Manifest.ContainsKey('Capabilities')) { $Manifest['Capabilities'] } else { @() })
    $seen  = @{}
    $i = 0
    foreach ($opt in @($Manifest['ConfigOptions'])) {
        $i++
        if ($opt -isnot [hashtable]) { $errors.Add("ConfigOptions[$i] is not a hashtable."); continue }

        $name = if ($opt.ContainsKey('Name')) { $opt['Name'] } else { $null }
        if ($name -isnot [string] -or [string]::IsNullOrWhiteSpace($name)) {
            $errors.Add("ConfigOptions[$i] has no Name.")
            $label = "ConfigOptions[$i]"
        } else {
            $label = "'$name'"
            if ($seen.ContainsKey($name.ToLowerInvariant())) { $errors.Add("Duplicate option Name $label.") }
            $seen[$name.ToLowerInvariant()] = $true
        }

        $type = if ($opt.ContainsKey('Type')) { $opt['Type'] } else { $null }
        $typeOk = ($type -is [string]) -and ($type -in $types)
        if (-not $typeOk) { $errors.Add("Option $label has an unknown or missing Type.") }

        $hooks = @(if ($opt.ContainsKey('Hooks') -and $null -ne $opt['Hooks']) { $opt['Hooks'] } else { @() })
        if ($hooks.Count -eq 0) {
            $errors.Add("Option $label has no Hooks.")
        } else {
            foreach ($h in $hooks) {
                if ($h -notin $caps) { $errors.Add("Option $label hook '$h' is not in the plugin's Capabilities.") }
            }
        }

        # Optional Browse hint for Path options.
        if ($opt.ContainsKey('PathKind')) {
            $kind = $opt['PathKind']
            if ($type -ne 'Path') { $errors.Add("Option $label PathKind applies only to Type Path.") }
            elseif ($kind -isnot [string] -or $kind -notin @('File', 'Folder', 'SaveFile')) {
                $errors.Add("Option $label PathKind must be File, Folder or SaveFile.")
            }
        }

        if ($opt.ContainsKey('Required') -and $opt['Required'] -isnot [bool]) {
            $errors.Add("Option $label Required must be a boolean.")
        }

        if ($typeOk -and $opt.ContainsKey('Default')) {
            $d = $opt['Default']
            $ok = switch ($type) {
                'Text'       { $d -is [string] }
                'Path'       { $d -is [string] }
                'Secret'     { $d -is [string] }
                # The form's Number field is Int32; a wider or fractional default could not round-trip.
                'Number'     { $d -is [int] -or ($d -is [long] -and $d -ge [int]::MinValue -and $d -le [int]::MaxValue) }
                'Bool'       { $d -is [bool] }
                'List'       { $d -is [System.Array] }
                'Table'      { $d -is [System.Collections.IDictionary] }
                'Credential' { $false }
            }
            if (-not $ok) { $errors.Add("Option $label Default is not compatible with Type $type.") }
        }
    }
    $errors.ToArray()
}

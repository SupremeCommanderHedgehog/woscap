# The only fields the GUI ever saves; Write-WoscapGuiSettingsFile drops anything else.
$script:WoscapGuiSettingsFields = @('Benchmark', 'XccdfPath', 'Targets', 'Profiles', 'AdvancedExpanded', 'ContentPath',
    'ThrottleLimit', 'JsonPath', 'ExportFormat', 'ContentDestination', 'IntegrationPath', 'Window')

function Get-WoscapGuiSettingsPath {
    <#
        .SYNOPSIS
        Returns the path of the per-user GUI settings file.
        .DESCRIPTION
        The single source of the settings path: %LOCALAPPDATA%\woscap\gui-settings.json.
        Tests mock this function so they never touch the real file.
        .OUTPUTS
        System.String
        .EXAMPLE
        Get-WoscapGuiSettingsPath
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    Join-Path $env:LOCALAPPDATA 'woscap\gui-settings.json'
}

function Read-WoscapGuiSettingsFile {
    <#
        .SYNOPSIS
        Reads the GUI settings file into a hashtable of raw, unvalidated fields.
        .DESCRIPTION
        Returns $null when the file is missing, empty, unreadable, not a JSON object, or its
        Version is not the integer 1. A nested Window object is returned as a hashtable too.
        Never throws; failures are reported with Write-Verbose only.
        .OUTPUTS
        System.Collections.Hashtable, or $null.
        .EXAMPLE
        $raw = Read-WoscapGuiSettingsFile
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    try {
        $path = Get-WoscapGuiSettingsPath
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
        $text = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        $obj = $text | ConvertFrom-Json -ErrorAction Stop
        if ($obj -isnot [System.Management.Automation.PSCustomObject]) { return $null }
        $raw = ConvertTo-WoscapGuiSettingsHashtable -InputObject $obj
        $version = $raw['Version']
        if (-not (Test-WoscapGuiSettingsInteger -Value $version) -or $version -ne 1) { return $null }
        $raw.Remove('Version')
        if ($raw['Window'] -is [System.Management.Automation.PSCustomObject]) {
            $raw['Window'] = ConvertTo-WoscapGuiSettingsHashtable -InputObject $raw['Window']
        }
        $raw
    } catch {
        Write-Verbose "GUI settings not loaded: $($_.Exception.Message)"
        $null
    }
}

function Write-WoscapGuiSettingsFile {
    <#
        .SYNOPSIS
        Saves GUI settings to the per-user settings file.
        .DESCRIPTION
        Keeps only the known settings fields, adds Version = 1, writes BOM-less UTF-8 JSON to
        <path>.tmp and moves it over the target, so a failed write never leaves a half file.
        Creates the folder if needed. Never throws: on failure it writes a warning, removes
        the temp file (best effort) and returns $false.
        .PARAMETER Settings
        The field values to save. Keys outside the known field set (credentials, results,
        filters) are dropped.
        .OUTPUTS
        System.Boolean. $true when the file was saved.
        .EXAMPLE
        Write-WoscapGuiSettingsFile -Settings @{ Targets = 'host1'; ThrottleLimit = 8 }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][hashtable] $Settings)
    $tmp = $null
    try {
        $path = Get-WoscapGuiSettingsPath
        $tmp = "$path.tmp"
        $data = [ordered]@{ Version = 1 }
        foreach ($name in $script:WoscapGuiSettingsFields) {
            if (-not $Settings.ContainsKey($name)) { continue }
            # Profiles must stay a JSON list even with zero or one entry.
            $data[$name] = if ($name -eq 'Profiles') { , @($Settings[$name]) } else { $Settings[$name] }
        }
        $json = ConvertTo-Json -InputObject $data -Depth 4
        $dir = Split-Path -Path $path -Parent
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
            New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
        }
        [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $tmp -Destination $path -Force -ErrorAction Stop
        $true
    } catch {
        Write-Warning "Could not save GUI settings: $($_.Exception.Message)"
        if ($tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        $false
    }
}

function Remove-WoscapGuiSettingsFile {
    <#
        .SYNOPSIS
        Deletes the per-user GUI settings file if it exists.
        .DESCRIPTION
        Used by the Reset settings menu item. Never throws: on failure it writes a warning
        and returns $false. Returns $true when no file remains.
        .OUTPUTS
        System.Boolean
        .EXAMPLE
        Remove-WoscapGuiSettingsFile
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    try {
        $path = Get-WoscapGuiSettingsPath
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
        $true
    } catch {
        Write-Warning "Could not delete GUI settings: $($_.Exception.Message)"
        $false
    }
}

function Resolve-WoscapGuiSettings {
    <#
        .SYNOPSIS
        Validates raw GUI settings against the current form. Pure: no WinForms code.
        .DESCRIPTION
        Keeps each known field that has the right type and passes its check; anything else
        is skipped so the control keeps its default. A non-empty path whose target no longer
        exists is dropped and counted in Cleared; empty paths mean "use the default" and are
        kept without counting. Missing profile entries are dropped, order kept, each counted.
        Window Width/Height are raised to the minimum size.
        .PARAMETER Raw
        Fields as returned by Read-WoscapGuiSettingsFile.
        .PARAMETER Allowed
        Hashtable with Benchmark and Format (the combos' current items), ThrottleMin and
        ThrottleMax (the throttle control's range), and MinWidth and MinHeight (the form's
        MinimumSize).
        .OUTPUTS
        System.Collections.Hashtable: @{ Values = <validated fields>; Cleared = <int> }.
        .EXAMPLE
        Resolve-WoscapGuiSettings -Raw $raw -Allowed @{ Benchmark = @('Windows11'); Format = @('Csv'); ThrottleMin = 1; ThrottleMax = 64; MinWidth = 760; MinHeight = 560 }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][hashtable] $Raw,
        [Parameter(Mandatory)][hashtable] $Allowed
    )
    $values = @{}
    $cleared = 0

    foreach ($pair in @(@('Benchmark', 'Benchmark'), @('ExportFormat', 'Format'))) {
        $v = $Raw[$pair[0]]
        if ($v -is [string] -and @($Allowed[$pair[1]]) -ccontains $v) { $values[$pair[0]] = $v }
    }
    $v = $Raw['Targets']
    if ($v -is [string] -and $v.Length -le 4096) { $values['Targets'] = $v }
    $v = $Raw['AdvancedExpanded']
    if ($v -is [bool]) { $values['AdvancedExpanded'] = $v }
    $v = $Raw['ThrottleLimit']
    if ((Test-WoscapGuiSettingsInteger -Value $v) -and $v -ge $Allowed['ThrottleMin'] -and $v -le $Allowed['ThrottleMax']) {
        $values['ThrottleLimit'] = [int]$v
    }

    # Field -> how its path must still exist.
    $pathRules = [ordered]@{
        XccdfPath = 'Leaf'; ContentPath = 'Container'; ContentDestination = 'Container'
        IntegrationPath = 'Container'; JsonPath = 'Parent'
    }
    foreach ($name in $pathRules.Keys) {
        $v = $Raw[$name]
        if ($v -isnot [string]) { continue }
        if ($v -eq '' -or (Test-WoscapGuiSettingsPathExists -Path $v -Kind $pathRules[$name])) { $values[$name] = $v }
        else { $cleared++ }
    }

    $v = $Raw['Profiles']
    if ($v -is [array]) {
        $kept = New-Object System.Collections.Generic.List[string]
        foreach ($p in $v) {
            if ($p -isnot [string] -or $p -eq '') { continue }
            if (Test-WoscapGuiSettingsPathExists -Path $p -Kind 'Leaf') { $kept.Add($p) } else { $cleared++ }
        }
        $values['Profiles'] = [string[]]$kept.ToArray()
    }

    $w = $Raw['Window']
    if ($w -is [System.Collections.IDictionary]) {
        $ints = @('X', 'Y', 'Width', 'Height')
        $ok = $w['Maximized'] -is [bool]
        foreach ($k in $ints) { if (-not (Test-WoscapGuiSettingsInteger -Value $w[$k])) { $ok = $false } }
        if ($ok) {
            $values['Window'] = @{
                X = [int]$w['X']; Y = [int]$w['Y']
                Width = [Math]::Max([int]$w['Width'], [int]$Allowed['MinWidth'])
                Height = [Math]::Max([int]$w['Height'], [int]$Allowed['MinHeight'])
                Maximized = [bool]$w['Maximized']
            }
        }
    }

    @{ Values = $values; Cleared = $cleared }
}

function Test-WoscapGuiSettingsInteger {
    <# True for a whole-number JSON value in Int32 range; bools, strings and fractions are not. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $Value)
    ($Value -is [int] -or $Value -is [long]) -and $Value -ge [int]::MinValue -and $Value -le [int]::MaxValue
}

function Test-WoscapGuiSettingsPathExists {
    <# Leaf: the file exists. Container: the folder exists. Parent: the folder holding it exists (none means the current folder). #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][ValidateSet('Leaf', 'Container', 'Parent')][string] $Kind)
    try {
        if ($Kind -eq 'Parent') {
            $parent = Split-Path -Path $Path -Parent
            return (-not $parent) -or (Test-Path -LiteralPath $parent -PathType Container)
        }
        Test-Path -LiteralPath $Path -PathType $Kind
    } catch { $false }
}

function ConvertTo-WoscapGuiSettingsHashtable {
    <# One level of PSCustomObject -> hashtable; ConvertFrom-Json has no -AsHashtable on 5.1. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] $InputObject)
    $h = @{}
    foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = $p.Value }
    $h
}

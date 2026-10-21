function Get-WoscapGuiScreenArea {
    <#
        .SYNOPSIS
        Returns the working area of every attached screen.
        .DESCRIPTION
        A seam over [System.Windows.Forms.Screen]::AllScreens so tests can fake the desktop
        layout. Saved window bounds are applied only when they intersect one of these areas.
        .OUTPUTS
        System.Drawing.Rectangle[]
        .EXAMPLE
        Get-WoscapGuiScreenArea
    #>
    [CmdletBinding()]
    [OutputType([System.Drawing.Rectangle[]])]
    param()
    , @([System.Windows.Forms.Screen]::AllScreens | ForEach-Object { $_.WorkingArea })
}

function Get-WoscapGuiSettingsState {
    <#
        .SYNOPSIS
        Reads the persisted fields from the main form's controls.
        .DESCRIPTION
        Returns the settings field set (see Write-WoscapGuiSettingsFile) as a hashtable. For a
        maximized or minimized window the Window entry uses RestoreBounds, so the next session
        restores to the size the user last had. Never reads credentials, results or filters.
        .PARAMETER Tag
        The main form's Tag hashtable.
        .PARAMETER Form
        The main form.
        .OUTPUTS
        System.Collections.Hashtable
        .EXAMPLE
        Get-WoscapGuiSettingsState -Tag $form.Tag -Form $form
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][System.Windows.Forms.Form] $Form)
    $bounds = if ($Form.WindowState -eq [System.Windows.Forms.FormWindowState]::Normal) { $Form.Bounds } else { $Form.RestoreBounds }
    @{
        Benchmark          = [string]$Tag['Benchmark'].SelectedItem
        XccdfPath          = [string]$Tag['Xccdf'].Text
        Targets            = [string]$Tag['Targets'].Text
        Profiles           = [string[]]@($Tag['Profiles'].Items | ForEach-Object { [string]$_ })
        AdvancedExpanded   = [bool]$Tag['AdvancedExpanded']
        ContentPath        = [string]$Tag['ContentPath'].Text
        ThrottleLimit      = [int]$Tag['ThrottleLimit'].Value
        JsonPath           = [string]$Tag['JsonPath'].Text
        ExportFormat       = [string]$Tag['Format'].SelectedItem
        ContentDestination = [string]$Tag['ContentDestination'].Text
        IntegrationPath    = [string]$Tag['IntegrationPath'].Text
        Window = @{
            X = $bounds.X; Y = $bounds.Y; Width = $bounds.Width; Height = $bounds.Height
            Maximized = $Form.WindowState -eq [System.Windows.Forms.FormWindowState]::Maximized
        }
    }
}

function Get-WoscapGuiSettingsAllowed {
    <# The -Allowed table for Resolve-WoscapGuiSettings, read from the live controls. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][System.Windows.Forms.Form] $Form)
    @{
        Benchmark   = @($Tag['Benchmark'].Items | ForEach-Object { [string]$_ })
        Format      = @($Tag['Format'].Items | ForEach-Object { [string]$_ })
        ThrottleMin = [int]$Tag['ThrottleLimit'].Minimum
        ThrottleMax = [int]$Tag['ThrottleLimit'].Maximum
        MinWidth    = $Form.MinimumSize.Width
        MinHeight   = $Form.MinimumSize.Height
    }
}

function Set-WoscapGuiSettingsValue {
    <#
        .SYNOPSIS
        Applies validated settings values (all but Window) to the main form's controls.
        .DESCRIPTION
        Sets only the fields present in -Values, then refreshes derived UI the same way user
        edits do: profile buttons, the default content-path hint, the Advanced layout, and any
        Content or Integrations grid that is already listed.
        .PARAMETER Tag
        The main form's Tag hashtable.
        .PARAMETER Values
        Validated fields, as produced by Resolve-WoscapGuiSettings or Get-WoscapGuiSettingsState.
        .EXAMPLE
        Set-WoscapGuiSettingsValue -Tag $form.Tag -Values $resolved.Values
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag, [Parameter(Mandatory)][AllowEmptyCollection()][hashtable] $Values)
    $text = @{ XccdfPath = 'Xccdf'; Targets = 'Targets'; ContentPath = 'ContentPath'; JsonPath = 'JsonPath'
        ContentDestination = 'ContentDestination'; IntegrationPath = 'IntegrationPath' }
    foreach ($field in $text.Keys) {
        if ($Values.ContainsKey($field)) { $Tag[$text[$field]].Text = [string]$Values[$field] }
    }
    if ($Values.ContainsKey('Benchmark') -and $Tag['Benchmark'].Items.Contains($Values['Benchmark'])) {
        $Tag['Benchmark'].SelectedItem = $Values['Benchmark']
    }
    if ($Values.ContainsKey('ExportFormat') -and $Tag['Format'].Items.Contains($Values['ExportFormat'])) {
        $Tag['Format'].SelectedItem = $Values['ExportFormat']
    }
    if ($Values.ContainsKey('ThrottleLimit')) { $Tag['ThrottleLimit'].Value = [decimal]$Values['ThrottleLimit'] }
    if ($Values.ContainsKey('Profiles')) {
        $Tag['Profiles'].Items.Clear()
        Add-WoscapGuiProfile -Tag $Tag -Path ([string[]]@($Values['Profiles']))
    }
    if ($Values.ContainsKey('AdvancedExpanded')) { Set-WoscapGuiAdvanced -Tag $Tag -Expanded ([bool]$Values['AdvancedExpanded']) }

    Update-WoscapGuiProfileButton -Tag $Tag
    Update-WoscapGuiContentHint -Tag $Tag
    # A listed grid follows its folder, as Browse does; an unlisted one lists on first view.
    if ($Values.ContainsKey('ContentDestination') -and $Tag['ContentLoaded']) { Update-WoscapGuiContentView -Tag $Tag }
    if ($Values.ContainsKey('IntegrationPath') -and $Tag['IntegrationLoaded']) { Update-WoscapGuiIntegrationView -Tag $Tag }
}

function Set-WoscapGuiWindowSettings {
    <#
        .SYNOPSIS
        Applies saved window bounds and state, if they are on a screen.
        .DESCRIPTION
        Applies the bounds only when the rectangle intersects one of -Area, so a window saved on
        a now-detached monitor reopens at the default size and position instead. Returns $true
        when applied.
        .PARAMETER Form
        The main form.
        .PARAMETER Window
        Hashtable with X, Y, Width, Height (already clamped to MinimumSize) and Maximized.
        .PARAMETER Area
        Screen working areas, from Get-WoscapGuiScreenArea.
        .OUTPUTS
        System.Boolean
        .EXAMPLE
        Set-WoscapGuiWindowSettings -Form $form -Window $values.Window -Area (Get-WoscapGuiScreenArea)
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][System.Windows.Forms.Form] $Form,
        [Parameter(Mandatory)][hashtable] $Window,
        [AllowEmptyCollection()][System.Drawing.Rectangle[]] $Area = @()
    )
    $rect = New-Object System.Drawing.Rectangle([int]$Window['X'], [int]$Window['Y'], [int]$Window['Width'], [int]$Window['Height'])
    if (@($Area | Where-Object { $_.IntersectsWith($rect) }).Count -eq 0) { return $false }
    $Form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
    # CenterScreen would move the window again when it is first shown.
    $Form.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
    $Form.Bounds = $rect
    if ($Window['Maximized']) { $Form.WindowState = [System.Windows.Forms.FormWindowState]::Maximized }
    $true
}

function Import-WoscapGuiSettings {
    <#
        .SYNOPSIS
        Loads the saved GUI settings into the main form.
        .DESCRIPTION
        Reads, validates and applies the per-user settings file, then refreshes derived UI the
        way user edits do. Window bounds are applied only when on a screen. When saved paths
        no longer exist, the Scan tab status says how many were cleared. A missing or bad file
        leaves the defaults. Never throws and never shows a dialog; problems go to Write-Verbose.
        .PARAMETER Tag
        The main form's Tag hashtable.
        .PARAMETER Form
        The main form, before it is shown.
        .EXAMPLE
        Import-WoscapGuiSettings -Tag $form.Tag -Form $form
    #>
    [CmdletBinding()]
    param([AllowNull()][hashtable] $Tag, [AllowNull()][System.Windows.Forms.Form] $Form)
    try {
        if (-not $Tag -or -not $Form) { return }
        $raw = Read-WoscapGuiSettingsFile
        if ($null -eq $raw) { return }
        $resolved = Resolve-WoscapGuiSettings -Raw $raw -Allowed (Get-WoscapGuiSettingsAllowed -Tag $Tag -Form $Form)
        Set-WoscapGuiSettingsValue -Tag $Tag -Values $resolved.Values
        if ($resolved.Values.ContainsKey('Window')) {
            [void](Set-WoscapGuiWindowSettings -Form $Form -Window $resolved.Values['Window'] -Area (Get-WoscapGuiScreenArea))
        }
        if ($resolved.Cleared -gt 0) {
            $Tag['Status'].Text = "$($resolved.Cleared) saved path(s) no longer exist and were cleared."
        }
    } catch {
        Write-Verbose "GUI settings not applied: $($_.Exception.Message)"
    }
}

function Export-WoscapGuiSettings {
    <#
        .SYNOPSIS
        Saves the main form's current settings to the per-user settings file.
        .DESCRIPTION
        Called on FormClosing. Reads the persisted fields from the controls (RestoreBounds when
        the window is not Normal) and writes them with Write-WoscapGuiSettingsFile. Never
        throws, so it can never cancel or break the close; a failure is a warning.
        .PARAMETER Tag
        The main form's Tag hashtable.
        .PARAMETER Form
        The main form.
        .EXAMPLE
        Export-WoscapGuiSettings -Tag $form.Tag -Form $form
    #>
    [CmdletBinding()]
    param([AllowNull()][hashtable] $Tag, [AllowNull()][System.Windows.Forms.Form] $Form)
    try {
        if (-not $Tag -or -not $Form) { return }
        [void](Write-WoscapGuiSettingsFile -Settings (Get-WoscapGuiSettingsState -Tag $Tag -Form $Form))
    } catch {
        Write-Warning "Could not save GUI settings: $($_.Exception.Message)"
    }
}

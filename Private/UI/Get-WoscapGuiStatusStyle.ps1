function Get-WoscapGuiStatusStyle {
    <#
        Pure helper: maps a woscap result Status to the row colors the GUI grid paints,
        so Open findings stand out at a glance. Returns an object with BackColor and
        ForeColor ([System.Drawing.Color]), or $null for an unknown/blank status (leave
        the row its default colors). No WinForms dependency -> unit-testable.

        Palette (familiar Excel-style tints with matching dark text for readability):
          Open           -> red     NotAFinding    -> green
          Not_Reviewed   -> amber   Not_Applicable -> gray
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Status)

    Add-Type -AssemblyName System.Drawing
    $rgb = { param($r, $g, $b) [System.Drawing.Color]::FromArgb($r, $g, $b) }

    switch ($Status) {
        'Open'           { [pscustomobject]@{ BackColor = (& $rgb 255 199 206); ForeColor = (& $rgb 156 0 6)   } }
        'NotAFinding'    { [pscustomobject]@{ BackColor = (& $rgb 198 239 206); ForeColor = (& $rgb 0 97 0)    } }
        'Not_Reviewed'   { [pscustomobject]@{ BackColor = (& $rgb 255 235 156); ForeColor = (& $rgb 156 101 0) } }
        'Not_Applicable' { [pscustomobject]@{ BackColor = (& $rgb 217 217 217); ForeColor = (& $rgb 89 89 89)  } }
        default          { $null }
    }
}

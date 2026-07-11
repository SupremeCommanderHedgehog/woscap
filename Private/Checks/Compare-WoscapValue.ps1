function Compare-WoscapValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('eq','ne','ge','le','in','includes','regex','exists')]
        [string] $Operator,
        [AllowNull()] [object] $Observed,
        [AllowNull()] [object] $Expected
    )
    switch ($Operator) {
        'eq'       { $Observed -eq $Expected }
        'ne'       { $Observed -ne $Expected }
        'ge'       { if ($null -eq $Observed -or $null -eq $Expected) { $false } else { [double]$Observed -ge [double]$Expected } }
        'le'       { if ($null -eq $Observed -or $null -eq $Expected) { $false } else { [double]$Observed -le [double]$Expected } }
        'in'       { @($Expected) -contains $Observed }
        'includes' { @($Observed) -contains $Expected }
        'regex'    { [bool]([string]$Observed -match [string]$Expected) }
        'exists'   {
            $present = $null -ne $Observed
            if ($Expected) { $present } else { -not $present }
        }
    }
}

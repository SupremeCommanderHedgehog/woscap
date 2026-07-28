function Compare-WoscapValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('eq','ne','ge','le','in','notin','includes','regex','exists','setequals','subsetof','supersetof','sequence')]
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
            # An empty collection means nothing was found, so it is absent -
            # $null -ne @() is $true, which would have reported "an antivirus
            # product exists" for a class that returned zero instances.
            $present = if ($null -eq $Observed) {
                $false
            } elseif ($Observed -is [System.Collections.ICollection] -and $Observed -isnot [string]) {
                @($Observed).Count -gt 0
            } else {
                $true
            }
            if ($Expected) { $present } else { -not $present }
        }
        'setequals' {
            $o = @($Observed | Where-Object { $null -ne $_ } | Sort-Object -Unique)
            $e = @($Expected | Where-Object { $null -ne $_ } | Sort-Object -Unique)
            if ($o.Count -ne $e.Count) { $false }
            elseif ($o.Count -eq 0) { $true }
            else { -not (Compare-Object -ReferenceObject $o -DifferenceObject $e) }
        }
        'notin' { -not (@($Expected) -contains $Observed) }
        'subsetof' {
            # "only assigned to X": every observed member must appear in Expected.
            # An empty observed set is compliant - nobody holds the right.
            $o = @($Observed | Where-Object { $null -ne $_ })
            $e = @($Expected | Where-Object { $null -ne $_ })
            @($o | Where-Object { $e -notcontains $_ }).Count -eq 0
        }
        'supersetof' {
            # "X must be defined": every expected member must appear in Observed.
            $o = @($Observed | Where-Object { $null -ne $_ })
            $e = @($Expected | Where-Object { $null -ne $_ })
            @($e | Where-Object { $o -notcontains $_ }).Count -eq 0
        }
        'sequence' {
            # Ordered equality, for REG_MULTI_SZ policies where order is the policy.
            $o = @($Observed | Where-Object { $null -ne $_ })
            $e = @($Expected | Where-Object { $null -ne $_ })
            if ($o.Count -ne $e.Count) { $false }
            else {
                $same = $true
                for ($i = 0; $i -lt $o.Count; $i++) {
                    if ([string]$o[$i] -ne [string]$e[$i]) { $same = $false; break }
                }
                $same
            }
        }
    }
}

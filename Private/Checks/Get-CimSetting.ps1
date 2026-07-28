function Get-CimSetting {
    <#
    .SYNOPSIS
        Read one property from a CIM class, memoized for the life of a scan.
    .DESCRIPTION
        Returns the property from every matching instance. A single instance
        yields a scalar; several yield a collection. An unreadable or absent
        class returns $null, which fails every operator except 'exists' with
        a falsy Expected - so a missing class is never a silent pass.

        The whole query is cached per (namespace, class, filter), and the
        property is projected afterwards, so reading three properties off
        Win32_DeviceGuard costs one query.
    #>
    [CmdletBinding()]
    param(
        [string] $Namespace = 'root\CIMV2',
        [Parameter(Mandatory)] [string] $ClassName,
        [Parameter(Mandatory)] [string] $Property,
        [string] $Filter
    )
    $key = "cim:$Namespace|$ClassName|$Filter"
    $instances = Get-WoscapCachedValue -Key $key -Producer {
        try {
            $splat = @{ Namespace = $Namespace; ClassName = $ClassName; ErrorAction = 'Stop' }
            if (-not [string]::IsNullOrWhiteSpace($Filter)) { $splat['Filter'] = $Filter }
            ,@(Get-CimInstance @splat)
        } catch {
            New-WoscapUnreadable -Reason "cannot query $Namespace/${ClassName}: $($_.Exception.Message)"
        }
    }
    # An unreadable class is not the same as a class with no instances. Returning
    # $null here would pass an 'exists:$false' check on a machine we never read.
    if (Test-WoscapUnreadable -Value $instances) { return $instances }
    if ($null -eq $instances) {
        # The producer always emits a collection or the sentinel, so $null here
        # means the cache layer lost the value rather than the class being empty.
        return (New-WoscapUnreadable -Reason "$ClassName query returned no usable result")
    }

    $all = @($instances)

    # Zero instances is real evidence (no antivirus registered, no non-system
    # share) and stays an empty set, which fails eq/ge/includes and exists:$true
    # as it should.
    if ($all.Count -eq 0) { return ,@() }

    # Instances exist but none carries the property: the descriptor names a
    # property this class does not have - a pack defect, not a reading. Left as
    # $null it passed the ne/notin/setequals family, so a mistyped Property
    # scored Pass.
    $carriers = @($all | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties[$Property] })
    if ($carriers.Count -eq 0) {
        return (New-WoscapUnreadable -Reason "$ClassName exposes no property '$Property'")
    }

    $values = @($carriers | ForEach-Object { $_.$Property })
    if ($values.Count -eq 1) { return $values[0] }
    $values
}

function New-WoscapUnreadable {
    <#
    .SYNOPSIS
        The sentinel a read helper returns when the underlying read FAILED, as
        distinct from succeeding and finding nothing.
    .DESCRIPTION
        Collapsing those two outcomes is the single most dangerous bug shape in
        this module. An empty result is legitimate evidence - nobody holds the
        right, no certificate matched, the group has no members - and several
        operators treat it as compliant. A failed read is not evidence at all,
        and must never produce Pass.

        Read helpers return this instead of $null / @() / a placeholder string
        when the read itself could not be performed. Test-Descriptor maps it to
        Result='Error' with the reason, so a permission failure is visible in
        the checklist rather than scored as compliance.
    #>
    [CmdletBinding()]
    param([string] $Reason = 'read failed')
    [pscustomobject]@{
        PSTypeName = 'Woscap.Unreadable'
        Reason     = $Reason
    }
}

function Test-WoscapUnreadable {
    <#
    .SYNOPSIS
        Whether a reading is the unreadable sentinel.
    .DESCRIPTION
        Also recognizes the sentinel when it arrives wrapped in a single-element
        collection, because a helper that emits it through a pipeline that the
        caller then wraps in @() would otherwise hide it.
    #>
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)] [AllowNull()] [object] $Value)
    process {
        if ($null -eq $Value) { return $false }
        $candidate = $Value
        if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
            $items = @($Value)
            if ($items.Count -ne 1) { return $false }
            $candidate = $items[0]
        }
        if ($null -eq $candidate) { return $false }
        [bool]($candidate.PSObject.TypeNames -contains 'Woscap.Unreadable')
    }
}

function Get-WoscapUnreadableReason {
    <#
    .SYNOPSIS
        The Reason carried by an unreadable sentinel, however it is wrapped.
    #>
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)
    $candidate = $Value
    if ($null -ne $Value -and $Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = @($Value)
        if ($items.Count -eq 1) { $candidate = $items[0] }
    }
    if ($null -eq $candidate) { return 'read failed' }
    if ($candidate.PSObject.Properties['Reason']) { return [string]$candidate.Reason }
    'read failed'
}

function New-WoscapRemediationResult {
    [CmdletBinding()]
    param(
        [string] $HostName = $env:COMPUTERNAME,
        [string] $StigId,
        [string[]] $StigIds,
        [string] $Title,
        [string] $CheckType,
        [string] $Action,
        [Parameter(Mandatory)]
        [ValidateSet('Planned','Applied','Failed','Skipped','Manual')]
        [string] $State,
        [string] $Before = 'Open',
        [string] $After = [char]0x2014,
        [string] $Detail = ''
    )
    # Every finding this action covers; a merged AuditPolicy action covers several.
    if (-not $PSBoundParameters.ContainsKey('StigIds')) { $StigIds = @($StigId) }
    [pscustomobject]@{
        Host      = $HostName
        StigId    = $StigId
        StigIds   = @($StigIds)
        Title     = $Title
        CheckType = $CheckType
        Action    = $Action
        State     = $State
        Before    = $Before
        After     = $After
        Detail    = $Detail
    }
}

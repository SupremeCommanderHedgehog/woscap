function New-WoscapResult {
    [CmdletBinding()]
    param(
        [string] $StigId,
        [string] $GroupId,
        [string] $RuleId,
        [string[]] $Cci = @(),
        [ValidateSet('high', 'medium', 'low')]
        [string] $Severity = 'medium',
        [string] $Title,
        [string] $CheckText,
        [string] $FixText,
        [string] $Discussion,
        [string] $CheckType,
        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'NA', 'NotReviewed', 'Error')]
        [string] $Result,
        [object] $Expected,
        [object] $Observed,
        [string] $FindingDetails,
        [string] $Comments,
        [object] $Exception,
        [string] $ComputerName = $env:COMPUTERNAME,
        [string] $Benchmark,
        [string] $BenchmarkVersion
    )
    [pscustomobject]@{
        Host             = $ComputerName
        Benchmark        = $Benchmark
        BenchmarkVersion = $BenchmarkVersion
        StigId           = $StigId
        GroupId          = $GroupId
        RuleId           = $RuleId
        Cci              = $Cci
        Severity         = $Severity
        Title            = $Title
        CheckText        = $CheckText
        FixText          = $FixText
        Discussion       = $Discussion
        CheckType        = $CheckType
        Expected         = $Expected
        Observed         = $Observed
        Result           = $Result
        Status           = ConvertTo-WoscapStatus -Result $Result
        FindingDetails   = $FindingDetails
        Comments         = $Comments
        Exception        = $Exception
    }
}

function ConvertTo-WoscapStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'NA', 'NotReviewed', 'Error')]
        [string] $Result
    )
    switch ($Result) {
        'Pass'        { 'NotAFinding' }
        'Fail'        { 'Open' }
        'NA'          { 'Not_Applicable' }
        'NotReviewed' { 'Not_Reviewed' }
        'Error'       { 'Not_Reviewed' }
    }
}

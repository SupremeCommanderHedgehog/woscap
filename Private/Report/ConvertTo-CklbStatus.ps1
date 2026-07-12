function ConvertTo-CklbStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('NotAFinding','Open','Not_Applicable','Not_Reviewed')]
        [string] $Status
    )
    switch ($Status) {
        'NotAFinding'    { 'not_a_finding' }
        'Open'           { 'open' }
        'Not_Applicable' { 'not_applicable' }
        'Not_Reviewed'   { 'not_reviewed' }
        default          { throw "ConvertTo-CklbStatus: unexpected status '$Status'." }
    }
}

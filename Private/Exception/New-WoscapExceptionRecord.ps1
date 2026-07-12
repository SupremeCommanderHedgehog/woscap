function New-WoscapExceptionRecord {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Exception)
    function Field([string] $Key) {
        if ($Exception.ContainsKey($Key)) { [string]$Exception[$Key] } else { '' }
    }
    [pscustomobject]@{
        Type          = Field 'Type'
        Justification = Field 'Justification'
        Author        = Field 'Author'
        Date          = Field 'Date'
        Expires       = Field 'Expires'
    }
}

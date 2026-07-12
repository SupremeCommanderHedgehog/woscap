function Test-WoscapExceptionActive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Exception,
        [datetime] $ReferenceDate = (Get-Date)
    )
    if (-not $Exception.ContainsKey('Expires') -or [string]::IsNullOrWhiteSpace([string]$Exception['Expires'])) {
        return $true
    }
    $expires = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Exception['Expires'], [ref]$expires)) {
        return ($expires.Date -ge $ReferenceDate.Date)
    }
    return $false   # unparseable Expires -> fail closed (treated as inactive)
}

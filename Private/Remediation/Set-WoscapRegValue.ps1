function Set-WoscapRegValue {
    # WRITE HELPER — part of the deliberate, gated remediation path. NOT an audit helper.
    # Every test mocks New-Item / Set-ItemProperty; this never runs live during dev/CI.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] $Data,
        [Parameter(Mandatory)] [ValidateSet('dword','string')] [string] $Kind
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    $propType = if ($Kind -eq 'dword') { 'DWord' } else { 'String' }
    Set-ItemProperty -LiteralPath $Path -Name $Name -Value $Data -Type $propType
}

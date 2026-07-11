function Get-ServiceState {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name)
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
    if (-not $svc) { return $null }
    [pscustomobject]@{ Name = $svc.Name; StartMode = $svc.StartMode; State = $svc.State }
}

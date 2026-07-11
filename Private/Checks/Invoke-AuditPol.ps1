function Invoke-AuditPol {
    [CmdletBinding()]
    param()
    (& auditpol.exe /get /category:* /r 2>$null) -join "`n"
}

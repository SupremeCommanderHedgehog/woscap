function Invoke-AuditPol {
    [CmdletBinding()]
    param()
    (& auditpol.exe /get /category:* /r) -join "`n"
}

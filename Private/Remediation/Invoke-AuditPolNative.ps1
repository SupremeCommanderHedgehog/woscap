function Invoke-AuditPolNative {
    # WRITE SEAM — the only code that invokes auditpol.exe with /set. Mocked in all tests;
    # never executed live during dev/CI. Mirrors the read-side Invoke-AuditPol seam.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string[]] $Arguments)
    $out = & auditpol.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol.exe $($Arguments -join ' ') failed (exit $LASTEXITCODE): $out"
    }
    $out
}

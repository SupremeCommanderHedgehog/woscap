function Invoke-SecEditExport {
    [CmdletBinding()]
    param()
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        $null = & secedit.exe /export /cfg $tmp /quiet 2>$null
        $content = Get-Content -Path $tmp -Raw
        if ([string]::IsNullOrWhiteSpace($content)) {
            throw 'secedit export produced no output (administrator privileges may be required to read the security policy).'
        }
        $content
    } finally {
        Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
    }
}

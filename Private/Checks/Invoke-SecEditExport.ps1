function Invoke-SecEditExport {
    [CmdletBinding()]
    param()
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        $null = & secedit.exe /export /cfg $tmp /quiet
        Get-Content -Path $tmp -Raw
    } finally {
        Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
    }
}

@{
    'Import-Findings' = {
        param([string] $Path, $Config)
        ConvertFrom-OpenVasReport -Path $Path
    }
    'Invoke-ExternalScan' = {
        param($Config)
        Write-Warning 'woscap: OpenVAS live GMP triggering is not implemented until Phase 4 (#23).'
        $null
    }
}

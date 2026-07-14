@{
    'Get-Targets'     = { param($Source, $Config) @('HOSTA', 'HOSTB') }
    'Import-Findings' = { param([string] $Path, $Config) @([pscustomobject]@{ Id = 'F1'; Source = 'Good' }) }
}

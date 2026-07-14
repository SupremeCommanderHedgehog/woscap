@{
    'Export-Findings' = { param($Result, $Config) [pscustomobject]@{ Pushed = @($Result).Count } }
    'New-Remediation' = { param($Result, [string] $Path, $Config) Set-Content -LiteralPath $Path -Value 'playbook'; $Path }
}

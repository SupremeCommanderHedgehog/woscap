BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
}

Describe 'Audit path is read-only' {
    It 'contains no write-capable cmdlets in Private source' {
        $forbidden = @(
            'Set-ItemProperty','New-ItemProperty','Remove-ItemProperty','New-Item','Set-Item',
            'Remove-Item','Set-Acl','Set-Service','Stop-Service','Start-Service','Restart-Service',
            'New-Service','Set-Content','Add-Content','Clear-Content','Out-File'
        )
        $files = Get-ChildItem -Path (Join-Path $ModuleRoot 'Private') -Recurse -Filter '*.ps1'
        $hits = foreach ($f in $files) {
            $text = Get-Content $f.FullName -Raw
            foreach ($p in $forbidden) {
                if ($text -match [regex]::Escape($p)) {
                    # Allow ONLY Invoke-SecEditExport.ps1's Remove-Item on the temp file it creates.
                    if ($f.Name -eq 'Invoke-SecEditExport.ps1' -and $p -eq 'Remove-Item') { continue }
                    "$($f.Name): $p"
                }
            }
        }
        $hits | Should -BeNullOrEmpty -Because "audit helpers must not mutate the system: $($hits -join '; ')"
    }
}

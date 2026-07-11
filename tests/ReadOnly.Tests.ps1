BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
}

Describe 'Audit path is read-only' {
    It 'contains no write-capable cmdlets in Private source' {
        $forbidden = @(
            'Set-ItemProperty','New-ItemProperty','Remove-ItemProperty','New-Item','Set-Item',
            'Remove-Item','Set-Acl','Set-Service','Stop-Service','Start-Service','Restart-Service',
            'New-Service','Set-Content','Add-Content','Clear-Content','Out-File',
            '\[System\.IO\.File\]::(Write|Create|Delete|Move|Copy|Append)',
            '\[System\.IO\.Directory\]::(Create|Delete|Move)',
            '\breg(\.exe)?\s+(add|delete|import|copy|restore)\b',
            # Conservative write-alias catch. If a future read-only helper legitimately
            # trips one of these short aliases (e.g. a variable/word), narrow the alternation
            # rather than weakening the .NET/reg/cmdlet patterns above.
            '\b(ni|si|rm|sc|rmdir|mkdir)\b'
        )
        $files = Get-ChildItem -Path (Join-Path $ModuleRoot 'Private') -Recurse -Filter '*.ps1'
        $hits = foreach ($f in $files) {
            $text = Get-Content $f.FullName -Raw
            foreach ($p in $forbidden) {
                if ($text -match $p) {
                    # Allow ONLY Invoke-SecEditExport.ps1's Remove-Item on the temp file it creates.
                    if ($f.Name -eq 'Invoke-SecEditExport.ps1' -and $p -eq 'Remove-Item') { continue }
                    "$($f.Name): $p"
                }
            }
        }
        $hits | Should -BeNullOrEmpty -Because "audit helpers must not mutate the system: $($hits -join '; ')"
    }
}

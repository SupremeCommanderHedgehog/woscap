BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
}

Describe 'Audit path is read-only' {
    It 'contains no write-capable cmdlets in Private source' {
        $forbidden = @(
            'Set-ItemProperty','New-ItemProperty','Remove-ItemProperty','New-Item','Set-Item',
            'Remove-Item','Set-Acl','Set-Service','Stop-Service','Start-Service','Restart-Service',
            'New-Service','Set-Content','Add-Content','Clear-Content','Out-File','Export-Csv',
            '\[System\.IO\.File\]::(Write|Create|Delete|Move|Copy|Append)',
            '\[System\.IO\.Directory\]::(Create|Delete|Move)',
            '\breg(\.exe)?\s+(add|delete|import|copy|restore)\b',
            # Conservative write-alias catch. If a future read-only helper legitimately
            # trips one of these short aliases (e.g. a variable/word), narrow the alternation
            # rather than weakening the .NET/reg/cmdlet patterns above.
            '\b(ni|si|rm|sc|rmdir|mkdir)\b'
        )
        # Private/Remediation/ is the deliberate, gated write path (Invoke-WoscapRemediation).
        # It is EXCLUDED from the audit-path forbidden-cmdlet scan by design; the scan-purity
        # test below keeps the guarantee that the SCAN path itself references no write helper.
        $files = Get-ChildItem -Path (Join-Path $ModuleRoot 'Private') -Recurse -Filter '*.ps1' |
            Where-Object { $_.DirectoryName -notmatch '[\\/]Remediation$' }
        $hits = foreach ($f in $files) {
            $text = Get-Content $f.FullName -Raw
            foreach ($p in $forbidden) {
                if ($text -match $p) {
                    # Allow ONLY Invoke-SecEditExport.ps1's Remove-Item on the temp file it creates.
                    if ($f.Name -eq 'Invoke-SecEditExport.ps1' -and $p -eq 'Remove-Item') { continue }
                    # Allow Push-WoscapScanPayload.ps1's New-Item: it runs inside a remote
                    # scriptblock to create the target-side per-run staging dir, not on the
                    # local audit host, so it doesn't mutate the machine under audit.
                    if ($f.Name -eq 'Push-WoscapScanPayload.ps1' -and $p -eq 'New-Item') { continue }
                    # Allow Remove-WoscapScanPayload.ps1's Remove-Item: it runs inside a remote
                    # scriptblock to clean the target-side per-run temp dir, not on the local
                    # audit host, so it doesn't mutate the machine under audit.
                    if ($f.Name -eq 'Remove-WoscapScanPayload.ps1' -and $p -eq 'Remove-Item') { continue }
                    # Reporter helpers (Private/Report/) legitimately write output files.
                    if ($f.DirectoryName -match '\\Report$' -and $p -in @('Set-Content','Add-Content','Out-File','Export-Csv')) { continue }
                    # Write-WoscapText is the reporters' single BOM-less output-writer; allow ONLY
                    # its [System.IO.File] output write, not any other mutation in that file.
                    if ($f.Name -eq 'Write-WoscapText.ps1' -and $p -eq '\[System\.IO\.File\]::(Write|Create|Delete|Move|Copy|Append)') { continue }
                    "$($f.Name): $p"
                }
            }
        }
        $hits | Should -BeNullOrEmpty -Because "audit helpers must not mutate the system: $($hits -join '; ')"
    }

    It 'scan entry point references no remediation write helper' {
        $scan = Get-Content (Join-Path $ModuleRoot 'Public/Invoke-WoscapScan.ps1') -Raw
        foreach ($helper in @('Set-WoscapRegValue','Invoke-AuditPolSet','Invoke-AuditPolNative','Get-WoscapRemediationPlan','Invoke-WoscapRemediation')) {
            $scan | Should -Not -Match ([regex]::Escape($helper)) -Because "a scan must never reference the write path ($helper)"
        }
    }
}

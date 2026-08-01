BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
}

Describe 'Module manifest export surface' {
    # woscap.psm1 exports Public/*.ps1 by basename at runtime, so a stale manifest
    # list silently shrinks (or inflates) the published API surface without any
    # import-time error. Assert the two agree mechanically instead of by discipline.
    It 'FunctionsToExport matches the files in Public/ exactly' {
        $manifest = Import-PowerShellDataFile -Path (Join-Path $ModuleRoot 'woscap.psd1')
        $declared = @($manifest.FunctionsToExport) | Sort-Object
        $onDisk = @(
            Get-ChildItem -Path (Join-Path $ModuleRoot 'Public') -Recurse -Filter '*.ps1' |
                ForEach-Object { $_.BaseName }
        ) | Sort-Object

        # Compare as delimited strings so a mismatch reports which names differ.
        ($declared -join ',') | Should -Be ($onDisk -join ',')
    }

    It 'does not use a wildcard export' {
        $manifest = Import-PowerShellDataFile -Path (Join-Path $ModuleRoot 'woscap.psd1')
        @($manifest.FunctionsToExport) | Should -Not -Contain '*'
        @($manifest.CmdletsToExport)   | Should -Not -Contain '*'
        @($manifest.AliasesToExport)   | Should -Not -Contain '*'
        @($manifest.VariablesToExport) | Should -Not -Contain '*'
    }
}

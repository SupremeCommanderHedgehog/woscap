BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Write-WoscapText' {
    It 'writes UTF-8 WITHOUT a BOM and round-trips the content' {
        InModuleScope woscap {
            $out = Join-Path ([System.IO.Path]::GetTempPath()) ("woscap-" + [System.Guid]::NewGuid() + ".txt")
            try {
                Write-WoscapText -Text '{"a":1}' -Path $out
                $bytes = [System.IO.File]::ReadAllBytes($out)
                # first bytes must NOT be the UTF-8 BOM (239,187,191)
                ($bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) | Should -BeFalse
                (Get-Content $out -Raw) | Should -Be '{"a":1}'
            } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
        }
    }
}

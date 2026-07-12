BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Export-WoscapJson' {
    It 'writes a JSON array of results (array even for a single result)' {
        InModuleScope woscap {
            $one = @( New-WoscapResult -StigId 'X' -Result 'Pass' -ComputerName 'PC1' )
            $out = Join-Path ([System.IO.Path]::GetTempPath()) ("woscap-" + [System.Guid]::NewGuid() + ".json")
            try {
                Export-WoscapJson -Result $one -Path $out
                (Get-Content $out -Raw).TrimStart()[0] | Should -Be '['   # array, not bare object
                (Get-Content $out -Raw | ConvertFrom-Json).StigId | Should -Be 'X'
            } finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
        }
    }
}

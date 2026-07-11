BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Pack = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/contentpack'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Import-ContentPack' {
    It 'merges declarative and override descriptors keyed by STIG ID' {
        InModuleScope woscap -Parameters @{ Pack = $script:Pack } {
            $p = Import-ContentPack -Path $Pack
            $p['WNTEST-00-000010'].Type | Should -Be 'Registry'
            $p['WNTEST-00-000020'].Type | Should -Be 'ScriptBlock'
            $p.Keys.Count | Should -Be 2
        }
    }
    It 'returns an empty hashtable for a pack folder with no files' {
        InModuleScope woscap {
            $empty = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid())
            New-Item -ItemType Directory -Path $empty | Out-Null
            try { (Import-ContentPack -Path $empty).Keys.Count | Should -Be 0 }
            finally { Remove-Item $empty -Recurse -Force }
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'New-WoscapContentSidecar' {
    It 'emits the canonical sidecar shape as JSON with retrievedRevision mirroring revision' {
        InModuleScope woscap {
            $json = New-WoscapContentSidecar -Benchmark 'Bench' -Revision '3' -Title 'T' -SourceUrl 'https://d/x.zip' -Etag '"e"' -LastModified 'LM' -ContentSha256 'HASH'
            $o = $json | ConvertFrom-Json
            $o.benchmark         | Should -Be 'Bench'
            $o.revision          | Should -Be '3'
            $o.retrievedRevision | Should -Be '3'
            $o.title             | Should -Be 'T'
            $o.sourceUrl         | Should -Be 'https://d/x.zip'
            $o.etag              | Should -Be '"e"'
            $o.lastModified      | Should -Be 'LM'
            $o.contentSha256     | Should -Be 'HASH'
        }
    }
}

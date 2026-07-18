BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Fixtures = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapContentReference' {
    It 'returns the newest matching-URL revision with its stored etag and hash' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-ref-' + [guid]::NewGuid().ToString('N'))
            try {
                foreach ($rev in '2','10') {
                    $rd = Join-Path (Join-Path $cache 'Bench') $rev
                    New-Item -ItemType Directory -Path $rd -Force | Out-Null
                    Copy-Item -LiteralPath (Join-Path $Fixtures 'sample-xccdf.xml') -Destination (Join-Path $rd 'U_x_Manual-xccdf.xml')
                    Set-Content -LiteralPath (Get-WoscapContentSidecarPath -RevisionDir $rd) -Value (@{
                        benchmark = 'Bench'; revision = $rev; sourceUrl = 'https://disa/x.zip'
                        etag = "`"etag-$rev`""
                    } | ConvertTo-Json)
                }
                $ref = Get-WoscapContentReference -CacheRoot $cache -Benchmark 'Bench' -SourceUrl 'https://disa/x.zip'
                $ref.Revision | Should -Be '10'         # numeric-newest, not '2'
                $ref.Etag     | Should -Be '"etag-10"'
                $ref.Xccdf    | Should -Match 'Bench[\\/]10[\\/].*_Manual-xccdf\.xml$'
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'returns $null when no cached revision has a matching sourceUrl' {
        InModuleScope woscap -Parameters @{ Fixtures = $script:Fixtures } {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-ref-' + [guid]::NewGuid().ToString('N'))
            try {
                $rd = Join-Path (Join-Path $cache 'Bench') '1'
                New-Item -ItemType Directory -Path $rd -Force | Out-Null
                Copy-Item -LiteralPath (Join-Path $Fixtures 'sample-xccdf.xml') -Destination (Join-Path $rd 'U_x_Manual-xccdf.xml')
                Set-Content -LiteralPath (Get-WoscapContentSidecarPath -RevisionDir $rd) -Value (@{
                    benchmark = 'Bench'; revision = '1'; sourceUrl = 'https://disa/OTHER.zip'
                } | ConvertTo-Json)
                Get-WoscapContentReference -CacheRoot $cache -Benchmark 'Bench' -SourceUrl 'https://disa/x.zip' | Should -BeNullOrEmpty
            } finally { Remove-Item -LiteralPath $cache -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'returns $null when the benchmark dir does not exist' {
        InModuleScope woscap {
            $cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-ref-' + [guid]::NewGuid().ToString('N'))
            Get-WoscapContentReference -CacheRoot $cache -Benchmark 'Missing' -SourceUrl 'https://disa/x.zip' | Should -BeNullOrEmpty
        }
    }
}

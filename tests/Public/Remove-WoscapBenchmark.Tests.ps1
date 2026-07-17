BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Remove-WoscapBenchmark' {
    BeforeEach {
        $script:Cache = Join-Path ([System.IO.Path]::GetTempPath()) ('woscap-rm-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $script:Cache 'Windows11\1') | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $script:Cache 'Windows11\2') | Out-Null
        Set-Content -Path (Join-Path $script:Cache 'Windows11\1\x.txt') -Value 'a'
        Set-Content -Path (Join-Path $script:Cache 'Windows11\2\x.txt') -Value 'b'
    }
    AfterEach { Remove-Item -LiteralPath $script:Cache -Recurse -Force -ErrorAction SilentlyContinue }

    It 'is exported as a public command' {
        Get-Command Remove-WoscapBenchmark -Module woscap | Should -Not -BeNullOrEmpty
    }
    It 'requires -Benchmark (no argless whole-cache wipe)' {
        (Get-Command Remove-WoscapBenchmark).Parameters['Benchmark'].Attributes.Mandatory |
            Should -Contain $true
    }
    It 'supports ShouldProcess (has -WhatIf / -Confirm)' {
        (Get-Command Remove-WoscapBenchmark).Parameters.Keys | Should -Contain 'WhatIf'
    }
    It 'removes the whole benchmark subtree when no -Revision is given' {
        Remove-WoscapBenchmark -Benchmark 'Windows11' -Destination $script:Cache -Confirm:$false
        (Join-Path $script:Cache 'Windows11') | Should -Not -Exist
    }
    It 'removes only the named revision when -Revision is given' {
        Remove-WoscapBenchmark -Benchmark 'Windows11' -Revision '1' -Destination $script:Cache -Confirm:$false
        (Join-Path $script:Cache 'Windows11\1') | Should -Not -Exist
        (Join-Path $script:Cache 'Windows11\2') | Should -Exist
    }
    It '-WhatIf removes nothing' {
        Remove-WoscapBenchmark -Benchmark 'Windows11' -Destination $script:Cache -WhatIf
        (Join-Path $script:Cache 'Windows11') | Should -Exist
    }
    It 'rejects an unsafe -Benchmark before deleting anything' {
        { Remove-WoscapBenchmark -Benchmark '..\..\evil' -Destination $script:Cache -Confirm:$false } |
            Should -Throw -ExpectedMessage '*unsafe benchmark name*'
        (Join-Path $script:Cache 'Windows11') | Should -Exist
    }
    It 'warns and no-ops when the target does not exist' {
        Remove-WoscapBenchmark -Benchmark 'Windows11' -Revision '9' -Destination $script:Cache -Confirm:$false -WarningAction SilentlyContinue
        (Join-Path $script:Cache 'Windows11\2') | Should -Exist
    }
    It 'returns the removed path' {
        $result = Remove-WoscapBenchmark -Benchmark 'Windows11' -Revision '1' -Destination $script:Cache -Confirm:$false
        $result | Should -Be (Join-Path $script:Cache 'Windows11\1')
    }
}

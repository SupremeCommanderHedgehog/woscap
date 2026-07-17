BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Assert-WoscapSafePathSegment' {
    It 'accepts a safe segment: <s>' -ForEach @(
        @{ s = '1' }, @{ s = 'Windows11' }, @{ s = 'V1R2' }, @{ s = 'unknown' },
        @{ s = 'U_MS_Windows_11_STIG_V1R1_Manual-xccdf.xml' }
    ) {
        InModuleScope woscap -Parameters @{ S = $s } {
            { Assert-WoscapSafePathSegment -Segment $S -Kind 'thing' } | Should -Not -Throw
        }
    }
    It 'rejects an unsafe segment: <s>' -ForEach @(
        @{ s = '.' }, @{ s = '..' }, @{ s = '..\..\evil' }, @{ s = 'a/b' },
        @{ s = 'a:b' }, @{ s = '' }, @{ s = 'a b' }
    ) {
        InModuleScope woscap -Parameters @{ S = $s } {
            { Assert-WoscapSafePathSegment -Segment $S -Kind 'thing' } | Should -Throw -ExpectedMessage '*unsafe thing*'
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Get-WoscapCachedValue' {
    It 'invokes the producer once for repeated reads of the same key' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            $script:hits = 0
            $p = { $script:hits++; 'value' }
            Get-WoscapCachedValue -Key 'k1' -Producer $p | Should -Be 'value'
            Get-WoscapCachedValue -Key 'k1' -Producer $p | Should -Be 'value'
            $script:hits | Should -Be 1
        }
    }
    It 'caches a null reading so the producer does not re-run' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            $script:hits = 0
            $p = { $script:hits++; $null }
            Get-WoscapCachedValue -Key 'k2' -Producer $p | Should -BeNullOrEmpty
            Get-WoscapCachedValue -Key 'k2' -Producer $p | Should -BeNullOrEmpty
            $script:hits | Should -Be 1
        }
    }
    It 'keeps distinct keys separate' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            Get-WoscapCachedValue -Key 'a' -Producer { 'A' } | Should -Be 'A'
            Get-WoscapCachedValue -Key 'b' -Producer { 'B' } | Should -Be 'B'
        }
    }
    It 'forgets everything after Clear-WoscapReadCache' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            $script:hits = 0
            $p = { $script:hits++; 'v' }
            $null = Get-WoscapCachedValue -Key 'k3' -Producer $p
            Clear-WoscapReadCache
            $null = Get-WoscapCachedValue -Key 'k3' -Producer $p
            $script:hits | Should -Be 2
        }
    }
    It 'does not cache a throwing producer' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            { Get-WoscapCachedValue -Key 'k4' -Producer { throw 'boom' } } | Should -Throw
            Get-WoscapCachedValue -Key 'k4' -Producer { 'recovered' } | Should -Be 'recovered'
        }
    }
    It 'preserves an array reading without unrolling it to a scalar' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            $v = Get-WoscapCachedValue -Key 'k5' -Producer { ,@('x','y') }
            @($v).Count | Should -Be 2
        }
    }
    It 'round-trips an EMPTY collection as a collection, not as $null' {
        InModuleScope woscap {
            # Emitting the cached value bare unrolls a collection into the
            # pipeline, so an empty one reached the caller as $null - a
            # different reading that passes ne/notin/setequals.
            Clear-WoscapReadCache
            $v = Get-WoscapCachedValue -Key 'k6' -Producer { ,@() }
            $null -eq $v      | Should -BeFalse
            @($v).Count       | Should -Be 0
        }
    }
    It 'round-trips a single-element collection without collapsing it to a scalar' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            $v = Get-WoscapCachedValue -Key 'k7' -Producer { ,@('only') }
            $v -is [array] | Should -BeTrue
        }
    }
    It 'still returns a scalar reading as a scalar' {
        InModuleScope woscap {
            Clear-WoscapReadCache
            Get-WoscapCachedValue -Key 'k8' -Producer { 42 } | Should -Be 42
        }
    }
}

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Select-WoscapGuiRow' {
    BeforeAll {
        $script:Rows = @(
            [pscustomobject]@{ StigId='V-1001'; Severity='high';   Status='Open';        Title='Disable SMBv1' }
            [pscustomobject]@{ StigId='V-1002'; Severity='medium'; Status='NotAFinding'; Title='Enable auditing' }
            [pscustomobject]@{ StigId='V-1003'; Severity='low';    Status='Open';        Title='Screen lock timeout' }
        )
    }
    It 'returns all rows when no filters are applied' {
        InModuleScope woscap -Parameters @{ Rows = $script:Rows } {
            @(Select-WoscapGuiRow -Result $Rows).Count | Should -Be 3
        }
    }
    It 'filters by severity' {
        InModuleScope woscap -Parameters @{ Rows = $script:Rows } {
            $r = @(Select-WoscapGuiRow -Result $Rows -Severity 'high')
            $r.Count | Should -Be 1
            $r[0].StigId | Should -Be 'V-1001'
        }
    }
    It 'filters by status' {
        InModuleScope woscap -Parameters @{ Rows = $script:Rows } {
            @(Select-WoscapGuiRow -Result $Rows -Status 'Open').Count | Should -Be 2
        }
    }
    It 'treats All as pass-through for severity and status' {
        InModuleScope woscap -Parameters @{ Rows = $script:Rows } {
            @(Select-WoscapGuiRow -Result $Rows -Severity 'All' -Status 'All').Count | Should -Be 3
        }
    }
    It 'matches Find against StigId (case-insensitive substring)' {
        InModuleScope woscap -Parameters @{ Rows = $script:Rows } {
            $r = @(Select-WoscapGuiRow -Result $Rows -Find 'v-1002')
            $r.Count | Should -Be 1
            $r[0].StigId | Should -Be 'V-1002'
        }
    }
    It 'matches Find against Title' {
        InModuleScope woscap -Parameters @{ Rows = $script:Rows } {
            @(Select-WoscapGuiRow -Result $Rows -Find 'audit').Count | Should -Be 1
        }
    }
    It 'treats Find as a literal substring, not a regex (dot is not a wildcard)' {
        InModuleScope woscap {
            $rows = @(
                [pscustomobject]@{ StigId='V-100X'; Severity='low'; Status='Open'; Title='decoy' }
                [pscustomobject]@{ StigId='V-100.'; Severity='low'; Status='Open'; Title='literal dot' }
            )
            $r = @(Select-WoscapGuiRow -Result $rows -Find 'V-100.')
            $r.Count | Should -Be 1
            $r[0].StigId | Should -Be 'V-100.'
        }
    }
    It 'combines all filters (AND semantics)' {
        InModuleScope woscap -Parameters @{ Rows = $script:Rows } {
            @(Select-WoscapGuiRow -Result $Rows -Severity 'low' -Status 'Open' -Find 'lock').Count | Should -Be 1
        }
    }
    It 'returns empty for an empty input set' {
        InModuleScope woscap {
            @(Select-WoscapGuiRow -Result @()).Count | Should -Be 0
        }
    }
}

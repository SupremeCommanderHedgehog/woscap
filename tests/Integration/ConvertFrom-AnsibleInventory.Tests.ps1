BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Dir = Join-Path (Split-Path $PSScriptRoot -Parent) 'fixtures/ansible'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'ConvertFrom-AnsibleInventory' {
    It 'parses an INI inventory, stripping per-host vars' {
        InModuleScope woscap -Parameters @{ Dir = $script:Dir } {
            $h = @(ConvertFrom-AnsibleInventory -Path (Join-Path $Dir 'inventory.ini'))
            $h | Should -Contain 'win01.example.com'
            $h | Should -Contain 'win02.example.com'
            $h | Should -Contain 'lnx01.example.com'
        }
    }
    It 'filters to a group when -Group is given (INI)' {
        InModuleScope woscap -Parameters @{ Dir = $script:Dir } {
            $h = @(ConvertFrom-AnsibleInventory -Path (Join-Path $Dir 'inventory.ini') -Group 'windows')
            $h.Count | Should -Be 2
            $h | Should -Not -Contain 'lnx01.example.com'
        }
    }
    It 'parses a YAML inventory to the same hosts as the INI' {
        InModuleScope woscap -Parameters @{ Dir = $script:Dir } {
            $ini  = @(ConvertFrom-AnsibleInventory -Path (Join-Path $Dir 'inventory.ini') | Sort-Object)
            $yaml = @(ConvertFrom-AnsibleInventory -Path (Join-Path $Dir 'inventory.yml') | Sort-Object)
            $yaml | Should -Be $ini
        }
    }
    It 'filters to a group when -Group is given (YAML)' {
        InModuleScope woscap -Parameters @{ Dir = $script:Dir } {
            @(ConvertFrom-AnsibleInventory -Path (Join-Path $Dir 'inventory.yml') -Group 'windows').Count | Should -Be 2
        }
    }
    It 'ignores [group:vars] and [group:children] section bodies when listing all hosts' {
        InModuleScope woscap -Parameters @{ Dir = $script:Dir } {
            $h = @(ConvertFrom-AnsibleInventory -Path (Join-Path $Dir 'inventory-children.ini'))
            $h | Should -Contain 'web01.example.com'
            $h | Should -Contain 'web02.example.com'
            $h | Should -Contain 'app01.example.com'
            # child GROUP names must not leak in as hosts
            $h | Should -Not -Contain 'web'
            $h | Should -Not -Contain 'app'
            $h | Should -Not -Contain 'production'
            # vars lines must not leak in as hosts
            $h | Should -Not -Contain 'ansible_user=admin'
        }
    }
    It 'expands a [group:children] group to the union of its child groups member hosts' {
        InModuleScope woscap -Parameters @{ Dir = $script:Dir } {
            $h = @(ConvertFrom-AnsibleInventory -Path (Join-Path $Dir 'inventory-children.ini') -Group 'production' | Sort-Object)
            $h | Should -Be @('app01.example.com', 'web01.example.com', 'web02.example.com')
        }
    }
    It 'returns hosts placed directly under all: > hosts: (no child group)' {
        InModuleScope woscap -Parameters @{ Dir = $script:Dir } {
            $h = @(ConvertFrom-AnsibleInventory -Path (Join-Path $Dir 'inventory-flat.yml'))
            $h | Should -Contain 'flat01.example.com'
            $h | Should -Contain 'flat02.example.com'
        }
    }
    It 'returns the flat hosts via -Group all as well' {
        InModuleScope woscap -Parameters @{ Dir = $script:Dir } {
            $h = @(ConvertFrom-AnsibleInventory -Path (Join-Path $Dir 'inventory-flat.yml') -Group 'all')
            $h | Should -Contain 'flat01.example.com'
            $h | Should -Contain 'flat02.example.com'
        }
    }
    It 'strips inline per-host vars to the bare hostname (YAML flow map)' {
        InModuleScope woscap -Parameters @{ Dir = $script:Dir } {
            $h = @(ConvertFrom-AnsibleInventory -Path (Join-Path $Dir 'inventory-flat.yml'))
            $h | Should -Contain 'flat02.example.com'
            ($h | Where-Object { $_ -like '*ansible_host*' -or $_ -like '*{*' }) | Should -BeNullOrEmpty
        }
    }
}

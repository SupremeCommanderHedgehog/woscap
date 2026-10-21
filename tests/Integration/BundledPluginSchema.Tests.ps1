BeforeDiscovery {
    $script:Names = 'OpenVAS', 'Ansible', 'Zabbix'
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Repo = Split-Path $PSScriptRoot -Parent | Split-Path -Parent
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

# Static scan: every -Config key a hook reads must be declared for that hook. Import-Findings
# also gets Public/Import-WoscapIntegration.ps1, which consumes Config for correlation.
Describe 'Bundled plugin config schemas' {
    It '<_> manifest schema is valid' -ForEach $script:Names {
        $m = Import-PowerShellDataFile -LiteralPath (Join-Path $script:Repo "Integrations/$_/plugin.psd1")
        InModuleScope woscap -Parameters @{ M = $m } {
            @($M.ConfigOptions).Count | Should -BeGreaterThan 0
            @(Test-WoscapPluginConfigSchema -Manifest $M) | Should -BeNullOrEmpty
        }
    }
    It '<_> declares every Config key its hooks read' -ForEach $script:Names {
        $name = $_
        $dir = Join-Path $script:Repo "Integrations/$name"
        $m = Import-PowerShellDataFile -LiteralPath (Join-Path $dir 'plugin.psd1')
        $src = Get-Content -LiteralPath (Join-Path $dir 'implementation.ps1') -Raw
        $extra = @{}
        if ($name -eq 'OpenVAS') {
            $extra['Import-Findings'] = Get-Content -LiteralPath (Join-Path $script:Repo 'Public/Import-WoscapIntegration.ps1') -Raw
        }
        $missing = @()
        foreach ($hook in $m.Capabilities) {
            $text = $src.Substring($src.IndexOf("'$hook'"))
            $next = [regex]::Match($text.Substring(1), "(?m)^    '[A-Za-z-]+' = \{")
            if ($next.Success) { $text = $text.Substring(0, $next.Index + 1) }
            if ($extra.ContainsKey($hook)) { $text += "`n" + $extra[$hook] }

            $keys = New-Object System.Collections.Generic.HashSet[string]
            foreach ($rx in '\$Config\.([A-Za-z_]\w*)', '\$Config\[\s*''([^'']+)''\s*\]', '\$Config\.ContainsKey\(\s*''([^'']+)''\s*\)') {
                foreach ($mm in [regex]::Matches($text, $rx)) { [void]$keys.Add($mm.Groups[1].Value) }
            }
            # foreach ($k in 'A','B') literal key lists
            foreach ($mm in [regex]::Matches($text, 'foreach \(\$\w+ in ((?:''[^'']+''(?:,\s*)?)+)\)')) {
                foreach ($q in [regex]::Matches($mm.Groups[1].Value, '''([^'']+)''')) { [void]$keys.Add($q.Groups[1].Value) }
            }
            [void]$keys.Remove('ContainsKey')
            $keys.Count | Should -BeGreaterThan 0 -Because "the scan must find keys for $name $hook"
            foreach ($k in $keys) {
                $decl = @($m.ConfigOptions | Where-Object { $_.Name -eq $k -and $hook -in @($_.Hooks) })
                if ($decl.Count -eq 0) { $missing += "$hook : $k" }
            }
        }
        $missing | Should -BeNullOrEmpty
    }
    It 'declares the Browse kind of every bundled Path option' {
        $want = @{ 'Ansible/ContentPath' = 'Folder'; 'Ansible/FactsPath' = 'SaveFile' }
        $got = @{}
        foreach ($name in 'OpenVAS', 'Ansible', 'Zabbix') {
            $m = Import-PowerShellDataFile -LiteralPath (Join-Path $script:Repo "Integrations/$name/plugin.psd1")
            foreach ($o in @($m.ConfigOptions | Where-Object { $_.Type -eq 'Path' })) {
                $got["$name/$($o.Name)"] = if ($o.ContainsKey('PathKind')) { $o.PathKind } else { '' }
            }
        }
        @($got.Keys | Sort-Object) | Should -Be @($want.Keys | Sort-Object)
        foreach ($k in $want.Keys) { $got[$k] | Should -Be $want[$k] -Because "$k Browse kind" }
    }
}

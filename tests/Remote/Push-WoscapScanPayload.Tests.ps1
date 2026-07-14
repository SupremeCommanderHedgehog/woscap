BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Push-WoscapScanPayload' {
    It 'ships only the curated module subset plus the one content pack' {
        InModuleScope woscap {
            $session = [pscustomobject]@{ ComputerName = 'SRV01' }
            $copied  = [System.Collections.Generic.List[object]]::new()
            Mock Invoke-WoscapRemoteCommand -ParameterFilter { $ScriptBlock -match 'New-Item' } { 'C:\Temp\woscap_run' }
            Mock Copy-WoscapModuleToSession { $copied.Add([pscustomobject]@{ Path = $Path; Destination = $Destination }) }

            Push-WoscapScanPayload -Session $session -RunId 'run' `
                -ModuleRoot 'C:\module' -ContentPath 'C:\module\Content\Windows11'

            $paths = @($copied.Path)
            @($paths | Where-Object { $_ -match 'woscap\.psd1$' }).Count | Should -Be 1
            @($paths | Where-Object { $_ -match 'woscap\.psm1$' }).Count | Should -Be 1
            @($paths | Where-Object { $_ -match '\\Private$' }).Count    | Should -Be 1
            @($paths | Where-Object { $_ -match '\\Public$' }).Count     | Should -Be 1
            $pack = @($copied | Where-Object { $_.Path -match 'Content\\Windows11$' })
            $pack.Count             | Should -Be 1
            $pack[0].Destination    | Should -Match '_content$'
            @($paths | Where-Object { $_ -match '\\STIG$|\\Profiles$|\\docs$|\\tests$' }).Count | Should -Be 0

            # The four module-subset files must land in the target-side run dir
            # returned by the remote New-Item, not anywhere else — a wrong $runDir
            # (or one that ignores the remote command's return) must fail here.
            $subset = @($copied | Where-Object { $_.Path -notmatch 'Content\\Windows11$' })
            $subset.Count | Should -Be 4
            ($subset.Destination | Sort-Object -Unique) | Should -Be 'C:\Temp\woscap_run'
        }
    }
}

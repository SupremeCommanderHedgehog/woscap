BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'ConvertTo-WoscapGuiScanParameter' {
    It 'returns only XccdfPath and Benchmark when nothing else is set' {
        InModuleScope woscap {
            $p = ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11'
            $p.Keys | Should -HaveCount 2
            $p['XccdfPath'] | Should -Be 'C:\x.xml'
            $p['Benchmark'] | Should -Be 'Windows11'
        }
    }
    It 'splits, trims, and drops empties for Targets -> ComputerName' {
        InModuleScope woscap {
            $p = ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11' -Targets 'SRV01, SRV02 ,,  SRV03'
            $p['ComputerName'] | Should -Be @('SRV01','SRV02','SRV03')
        }
    }
    It 'omits ComputerName when Targets is blank' {
        InModuleScope woscap {
            $p = ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11' -Targets '   '
            $p.ContainsKey('ComputerName') | Should -BeFalse
        }
    }
    It 'passes multiple profiles in order and drops blank entries' {
        InModuleScope woscap {
            $p = ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11' -ProfilePath @('C:\a.psd1', '  ', 'C:\b.psd1')
            @($p['ProfilePath']) | Should -Be @('C:\a.psd1', 'C:\b.psd1')
        }
    }
    It 'omits ProfilePath when no non-blank profile is given' {
        InModuleScope woscap {
            (ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11').ContainsKey('ProfilePath') | Should -BeFalse
            (ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11' -ProfilePath @(' ')).ContainsKey('ProfilePath') | Should -BeFalse
        }
    }
    It 'includes ContentPath when set and omits it when blank' {
        InModuleScope woscap {
            (ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11' -ContentPath 'D:\pack')['ContentPath'] | Should -Be 'D:\pack'
            (ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11' -ContentPath ' ').ContainsKey('ContentPath') | Should -BeFalse
        }
    }
    It 'includes JsonPath when set and omits it when blank' {
        InModuleScope woscap {
            (ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11' -JsonPath 'C:\o\r.json')['JsonPath'] | Should -Be 'C:\o\r.json'
            (ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11' -JsonPath '').ContainsKey('JsonPath') | Should -BeFalse
        }
    }
    It 'includes ThrottleLimit only when it differs from the cmdlet default' {
        InModuleScope woscap {
            $default = (Get-WoscapGuiScanDefault).ThrottleLimit
            (ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11' -ThrottleLimit $default).ContainsKey('ThrottleLimit') | Should -BeFalse
            (ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11' -ThrottleLimit ($default + 4))['ThrottleLimit'] | Should -Be ($default + 4)
            (ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11').ContainsKey('ThrottleLimit') | Should -BeFalse
        }
    }
    It 'includes Credential when supplied' {
        InModuleScope woscap {
            $cred = [pscredential]::new('u', (ConvertTo-SecureString 'p' -AsPlainText -Force))
            (ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11' -Credential $cred).ContainsKey('Credential') | Should -BeTrue
        }
    }
}

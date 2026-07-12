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
    It 'includes ProfilePath when set and omits it when blank' {
        InModuleScope woscap {
            (ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11' -ProfilePath 'C:\p.psd1')['ProfilePath'] | Should -Be 'C:\p.psd1'
            (ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11').ContainsKey('ProfilePath') | Should -BeFalse
        }
    }
    It 'includes Credential when supplied' {
        InModuleScope woscap {
            $cred = [pscredential]::new('u', (ConvertTo-SecureString 'p' -AsPlainText -Force))
            (ConvertTo-WoscapGuiScanParameter -XccdfPath 'C:\x.xml' -Benchmark 'Windows11' -Credential $cred).ContainsKey('Credential') | Should -BeTrue
        }
    }
}

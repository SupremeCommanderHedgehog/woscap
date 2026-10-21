BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:RealXccdf = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) `
        'STIG/_extracted/U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Real Windows 11 XCCDF smoke' -Skip:(-not (Test-Path (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'STIG/_extracted/U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml'))) {
    It 'parses the real benchmark into 257 rules' {
        InModuleScope woscap -Parameters @{ Xccdf = $script:RealXccdf } {
            (Import-Xccdf -Path $Xccdf).Count | Should -Be 257
        }
    }
    It 'runs a full scan and returns a result per rule' {
        $res = Invoke-WoscapScan -XccdfPath $script:RealXccdf -Benchmark Windows11 -Quiet
        @($res).Count | Should -Be 257
        ($res | Where-Object StigId -eq 'WN11-00-000165').Status | Should -BeIn @('Open','NotAFinding')
        ($res | Where-Object Status -eq 'Not_Reviewed').Count | Should -BeLessThan 160
    }
}

Describe 'Real Defender Firewall XCCDF smoke' -Skip:(-not (Test-Path (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'STIG/U_MS_Windows_Defender_Firewall_V2R2_STIG/U_MS_Windows_Defender_Firewall_V2R2_Manual_STIG/U_MS_Windows_Defender_Firewall_STIG_V2R2_Manual-xccdf.xml'))) {
    BeforeAll {
        $script:FirewallXccdf = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) `
            'STIG/U_MS_Windows_Defender_Firewall_V2R2_STIG/U_MS_Windows_Defender_Firewall_V2R2_Manual_STIG/U_MS_Windows_Defender_Firewall_STIG_V2R2_Manual-xccdf.xml'
    }
    It 'parses the real benchmark into 21 rules' {
        InModuleScope woscap -Parameters @{ Xccdf = $script:FirewallXccdf } {
            (Import-Xccdf -Path $Xccdf).Count | Should -Be 21
        }
    }
    It 'runs a read-only scan with every rule authored and none in Error' {
        $res = Invoke-WoscapScan -XccdfPath $script:FirewallXccdf -Benchmark DefenderFirewall -Quiet
        @($res).Count | Should -Be 21
        # WNFWA-000100 is Manual; off-domain it is NA, so Not_Reviewed is at most 1.
        @($res | Where-Object Status -eq 'Not_Reviewed').Count | Should -BeLessOrEqual 1
        @($res | Where-Object Status -eq 'Error') | Should -BeNullOrEmpty
        ($res | Where-Object StigId -eq 'WNFWA-000002').Status | Should -BeIn @('Open', 'NotAFinding')
    }
}

Describe 'Real Defender Antivirus XCCDF smoke' -Skip:(-not (Test-Path (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'STIG/U_MS_Defender_Antivirus_V2R10_STIG.zip'))) {
    BeforeAll {
        # Read from the licensed archive; the XCCDF is copied only into TestDrive.
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $zipPath = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'STIG/U_MS_Defender_Antivirus_V2R10_STIG.zip'
        $script:AvXccdf = Join-Path $TestDrive 'U_MS_Defender_Antivirus_STIG_V2R10_Manual-xccdf.xml'
        $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            $entry = @($zip.Entries | Where-Object { $_.FullName -like '*Manual-xccdf.xml' })[0]
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $script:AvXccdf, $true)
        } finally { $zip.Dispose() }
    }
    It 'parses the real benchmark into 67 rules' {
        InModuleScope woscap -Parameters @{ Xccdf = $script:AvXccdf } {
            (Import-Xccdf -Path $Xccdf).Count | Should -Be 67
        }
    }
    It 'runs a read-only scan with every rule authored and Error only on access-protected keys' {
        $res = Invoke-WoscapScan -XccdfPath $script:AvXccdf -Benchmark DefenderAntivirus -Quiet
        @($res).Count | Should -Be 67
        # WNDF-AV-000068 is the only Manual rule.
        @($res | Where-Object Result -eq 'NotReviewed').StigId | Should -Be @('WNDF-AV-000068')
        # Exclusions and Policy Manager deny non-elevated reads (and Exclusions may stay hidden
        # from admins under WNDF-AV-000100); those fail closed. Nothing else may Error.
        foreach ($e in @($res | Where-Object Result -eq 'Error')) {
            "$($e.Observed)" | Should -Match 'cannot read HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\(Exclusions|Policy Manager)\\' -Because $e.StigId
        }
        ($res | Where-Object StigId -eq 'WNDF-AV-000003').Status | Should -BeIn @('Open', 'NotAFinding')
    }
}

Describe 'Real Mozilla Firefox XCCDF smoke' -Skip:(-not (Test-Path (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'STIG/U_MOZ_Firefox_V6R9_STIG.zip'))) {
    BeforeAll {
        # Read from the licensed archive; the XCCDF is copied only into TestDrive.
        Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
        $zipPath = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'STIG/U_MOZ_Firefox_V6R9_STIG.zip'
        $script:FfXccdf = Join-Path $TestDrive 'U_MOZ_Firefox_STIG_V6R9_Manual-xccdf.xml'
        $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            $entry = @($zip.Entries | Where-Object { $_.FullName -like '*Manual-xccdf.xml' })[0]
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $script:FfXccdf, $true)
        } finally { $zip.Dispose() }
    }
    It 'parses the real benchmark into 33 rules' {
        InModuleScope woscap -Parameters @{ Xccdf = $script:FfXccdf } {
            (Import-Xccdf -Path $Xccdf).Count | Should -Be 33
        }
    }
    It 'runs a read-only scan with no Error and only the Manual and omitted rules unreviewed' {
        $res = Invoke-WoscapScan -XccdfPath $script:FfXccdf -Benchmark Firefox -Quiet
        @($res).Count | Should -Be 33
        @($res | Where-Object Result -eq 'Error') | Should -BeNullOrEmpty
        # Six Preferences rules are Manual; version, MIME-action and DoD-root rules have no descriptor.
        @($res | Where-Object Result -eq 'NotReviewed' | ForEach-Object StigId | Sort-Object) | Should -Be @(
            'FFOX-00-000001', 'FFOX-00-000003', 'FFOX-00-000004', 'FFOX-00-000006', 'FFOX-00-000010',
            'FFOX-00-000011', 'FFOX-00-000016', 'FFOX-00-000025', 'FFOX-00-000026')
        ($res | Where-Object StigId -eq 'FFOX-00-000014').Status | Should -BeIn @('Open', 'NotAFinding')
    }
}

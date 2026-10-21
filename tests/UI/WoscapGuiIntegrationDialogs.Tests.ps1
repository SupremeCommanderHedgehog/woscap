BeforeDiscovery {
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms

    # Every visible control of $Form must stay inside its parent at default and minimum size.
    InModuleScope woscap {
        function script:Get-TestOverflow([System.Windows.Forms.Form] $Form) {
            $walk = { param($c) foreach ($child in $c.Controls) { $child; & $walk $child } }
            $bad = [System.Collections.Generic.List[string]]::new()
            $checked = 0
            foreach ($size in $Form.Size, $Form.MinimumSize) {
                $Form.Size = $size
                [System.Windows.Forms.Application]::DoEvents()
                foreach ($c in @(& $walk $Form)) {
                    if (-not $c.Visible) { continue }
                    $checked++
                    $w = $c.Parent.ClientSize.Width; $h = $c.Parent.ClientSize.Height
                    if ($c.Left -lt 0 -or $c.Right -gt $w -or $c.Top -lt 0 -or $c.Bottom -gt $h) {
                        $bad.Add(('{0} "{1}" L={2} R={3} T={4} B={5} parent={6}x{7} at {8}x{9}' -f
                            $c.GetType().Name, $c.Text, $c.Left, $c.Right, $c.Top, $c.Bottom, $w, $h, $size.Width, $size.Height))
                    }
                }
            }
            @{ Checked = $checked; Bad = $bad }
        }
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Integration source dialog' -Skip:(-not $script:IsSta) {
    BeforeEach {
        Mock -ModuleName woscap Show-WoscapGuiMessage { }
        Mock -ModuleName woscap Get-WoscapGuiCredential { }
        Mock -ModuleName woscap Get-WoscapGuiOpenPath { @() }
        Mock -ModuleName woscap Get-WoscapGuiFolderPath { $null }
        Mock -ModuleName woscap Get-WoscapGuiSavePath { $null }
        $script:Report = Join-Path $TestDrive 'report.xml'
        Set-Content -LiteralPath $script:Report -Value '<report/>'
    }

    It 'Targets: the source file is optional and comes back trimmed' {
        InModuleScope woscap -Parameters @{ Report = $script:Report } {
            param($Report)
            $d = New-WoscapGuiIntegrationSourceDialog -Mode Targets -Integration 'Ansible'
            try {
                $d.Text | Should -Match 'Ansible'
                $d.Tag['Correlate'] | Should -BeNullOrEmpty -Because 'targets have nothing to correlate'
                (Get-WoscapGuiIntegrationSourceChoice -Tag $d.Tag).Path | Should -Be ''
                $d.Tag['Path'].Text = "  $Report  "
                (Get-WoscapGuiIntegrationSourceChoice -Tag $d.Tag).Path | Should -Be $Report
            } finally { $d.Dispose() }
        }
    }

    It 'Findings: a report file is required and must exist; the dialog stays open with a message' {
        InModuleScope woscap -Parameters @{ Report = $script:Report } {
            param($Report)
            $d = New-WoscapGuiIntegrationSourceDialog -Mode Findings -Integration 'OpenVAS' -CanCorrelate
            try {
                Confirm-WoscapGuiIntegrationSourceDialog -Form $d | Should -BeFalse
                $d.Tag['Path'].Text = Join-Path $Report 'missing.xml'
                Confirm-WoscapGuiIntegrationSourceDialog -Form $d | Should -BeFalse
                Should -Invoke Show-WoscapGuiMessage -Times 2 -Exactly
                $d.DialogResult | Should -Be ([System.Windows.Forms.DialogResult]::None)
                $d.Tag['Path'].Text = $Report
                $d.Tag['Correlate'].Checked = $true
                Confirm-WoscapGuiIntegrationSourceDialog -Form $d | Should -BeTrue
                $d.DialogResult | Should -Be ([System.Windows.Forms.DialogResult]::OK)
                $c = Get-WoscapGuiIntegrationSourceChoice -Tag $d.Tag
                $c.Path | Should -Be $Report
                $c.Correlate | Should -BeTrue
            } finally { $d.Dispose() }
        }
    }

    It 'Targets: a source file that does not exist is rejected' {
        InModuleScope woscap -Parameters @{ Report = $script:Report } {
            param($Report)
            $d = New-WoscapGuiIntegrationSourceDialog -Mode Targets -Integration 'Ansible'
            try {
                $d.Tag['Path'].Text = "$Report.nope"
                Confirm-WoscapGuiIntegrationSourceDialog -Form $d | Should -BeFalse
                $d.Tag['Path'].Text = ''
                Confirm-WoscapGuiIntegrationSourceDialog -Form $d | Should -BeTrue
            } finally { $d.Dispose() }
        }
    }

    It 'disables Correlate when there are no current scan results' {
        InModuleScope woscap {
            $d = New-WoscapGuiIntegrationSourceDialog -Mode Findings -Integration 'OpenVAS'
            try {
                $d.Tag['Correlate'].Enabled | Should -BeFalse
                $d.Tag['Correlate'].Checked | Should -BeFalse
                (Get-WoscapGuiIntegrationSourceChoice -Tag $d.Tag -SkipValidation).Correlate | Should -BeFalse
            } finally { $d.Dispose() }
        }
    }

    It 'Browse fills the path from the open-file seam and a cancelled Browse keeps it' {
        InModuleScope woscap {
            $d = New-WoscapGuiIntegrationSourceDialog -Mode Findings -Integration 'OpenVAS'
            try {
                $d.Tag['Path'].Text = 'C:\keep.xml'
                Invoke-WoscapGuiIntegrationSourceBrowse -Tag $d.Tag
                $d.Tag['Path'].Text | Should -Be 'C:\keep.xml'
                Mock Get-WoscapGuiOpenPath { @('C:\picked\report.xml') }
                Invoke-WoscapGuiIntegrationSourceBrowse -Tag $d.Tag
                $d.Tag['Path'].Text | Should -Be 'C:\picked\report.xml'
            } finally { $d.Dispose() }
        }
    }

    It 'never makes Next the AcceptButton; Cancel is the CancelButton' {
        InModuleScope woscap {
            $d = New-WoscapGuiIntegrationSourceDialog -Mode Targets -Integration 'Ansible'
            try {
                $d.AcceptButton | Should -BeNullOrEmpty
                $d.CancelButton | Should -Be $d.Tag['Cancel']
                $d.Tag['Next'].DialogResult | Should -Be ([System.Windows.Forms.DialogResult]::None)
            } finally { $d.Dispose() }
        }
    }

    It 'keeps every control inside its parent at default and minimum size (<Mode>)' -ForEach @(@{ Mode = 'Targets' }, @{ Mode = 'Findings' }) {
        InModuleScope woscap -Parameters @{ Mode = $Mode } {
            param($Mode)
            $d = New-WoscapGuiIntegrationSourceDialog -Mode $Mode -Integration ('VeryLongIntegrationName' * 8) -CanCorrelate
            try {
                $d.Show(); [System.Windows.Forms.Application]::DoEvents()
                $d.Tag['Path'].Text = 'C:\' + ('very\long\path\' * 30) + 'report.xml'
                $r = Get-TestOverflow $d
                $r.Checked | Should -BeGreaterThan 4
                $r.Bad | Should -BeNullOrEmpty
            } finally { $d.Close(); $d.Dispose() }
        }
    }
}

Describe 'Integration findings dialog' -Skip:(-not $script:IsSta) {
    BeforeEach {
        Mock -ModuleName woscap Show-WoscapGuiMessage { }
        InModuleScope woscap {
            $script:findings = @(
                [pscustomobject]@{ Host = '10.0.0.5'; Severity = 'high'; Id = '1.3.6.1'; Name = 'Weak TLS'; Cve = @('CVE-1', 'CVE-2'); Cce = @(); Port = '443/tcp' }
                [pscustomobject]@{ Host = '10.0.0.6'; Severity = 'low'; Id = '1.3.6.2'; Name = 'Banner'; Cve = @(); Cce = @('CCE-9'); Port = '22/tcp' }
            )
            $script:links = @([pscustomobject]@{ Host = 'srv1'; RuleId = 'SV-1'; FindingId = '1.3.6.1'; MatchedOn = 'CVE-1' })
        }
    }

    It 'lists every finding with list values joined, and no links grid when not correlated' {
        InModuleScope woscap {
            $d = New-WoscapGuiIntegrationFindingsDialog -Title 'Findings' -Findings $script:findings -Links $null
            try {
                $g = $d.Tag['Findings']
                $g.Rows.Count | Should -Be 2
                @($g.Columns | ForEach-Object HeaderText) | Should -Be @('Host', 'Severity', 'Id', 'Name', 'CVE', 'CCE', 'Port')
                $g.Rows[0].Cells[4].Value | Should -Be 'CVE-1, CVE-2'
                $g.Rows[1].Cells[5].Value | Should -Be 'CCE-9'
                $d.Tag['Links'] | Should -BeNullOrEmpty
                $d.Tag['Summary'].Text | Should -Match '2 finding'
            } finally { $d.Dispose() }
        }
    }

    It 'adds the links grid and count when correlated, even with zero links' {
        InModuleScope woscap {
            $d = New-WoscapGuiIntegrationFindingsDialog -Title 'Findings' -Findings $script:findings -Links $script:links
            try {
                $d.Tag['Links'].Rows.Count | Should -Be 1
                @($d.Tag['Links'].Columns | ForEach-Object HeaderText) | Should -Be @('Host', 'Rule', 'Finding', 'Matched on')
                $d.Tag['Summary'].Text | Should -Match '1 link'
            } finally { $d.Dispose() }
            $d = New-WoscapGuiIntegrationFindingsDialog -Title 'Findings' -Findings $script:findings -Links @()
            try {
                $d.Tag['Links'] | Should -Not -BeNullOrEmpty
                $d.Tag['Summary'].Text | Should -Match '0 link'
            } finally { $d.Dispose() }
        }
    }

    It 'handles findings without the usual properties' {
        InModuleScope woscap {
            $d = New-WoscapGuiIntegrationFindingsDialog -Title 'x' -Findings @('plain string', [pscustomobject]@{ Other = 1 }) -Links $null
            try { $d.Tag['Findings'].Rows.Count | Should -Be 2 } finally { $d.Dispose() }
        }
    }

    It 'has a Close button that is the CancelButton' {
        InModuleScope woscap {
            $d = New-WoscapGuiIntegrationFindingsDialog -Title 'x' -Findings @() -Links $null
            try { $d.CancelButton | Should -Be $d.Tag['Close'] } finally { $d.Dispose() }
        }
    }

    It 'keeps every control inside its parent at default and minimum size with long values and many rows' {
        InModuleScope woscap {
            $many = @(foreach ($i in 1..200) {
                [pscustomobject]@{ Host = ('host' * 20) + $i; Severity = 'medium'; Id = "id$i"; Name = ('Long finding name ' * 10)
                    Cve = @(1..15 | ForEach-Object { "CVE-2020-$_" }); Cce = @(); Port = '1/tcp' }
            })
            $links = @(foreach ($i in 1..50) { [pscustomobject]@{ Host = 'h'; RuleId = "SV-$i"; FindingId = "id$i"; MatchedOn = 'CVE-1' } })
            $d = New-WoscapGuiIntegrationFindingsDialog -Title ('Findings ' * 30) -Findings $many -Links $links
            try {
                $d.Show(); [System.Windows.Forms.Application]::DoEvents()
                $r = Get-TestOverflow $d
                $r.Checked | Should -BeGreaterThan 3
                $r.Bad | Should -BeNullOrEmpty
            } finally { $d.Close(); $d.Dispose() }
        }
    }
}

Describe 'Format-WoscapGuiIntegrationReturn' {
    It 'summarises <Why>' -ForEach @(
        @{ Why = 'nothing'; In = @(); Like = '(no return value)' }
        @{ Why = 'a bool'; In = @($true); Like = 'True' }
        @{ Why = 'a string'; In = @('C:\out.yml'); Like = 'C:\out.yml' }
        @{ Why = 'an object'; In = @([pscustomobject]@{ FactsPath = 'C:\f.json'; Count = 3 }); Like = '*FactsPath=C:\f.json*Count=3*' }
    ) {
        InModuleScope woscap -Parameters @{ In = $In; Like = $Like } {
            param($In, $Like)
            Format-WoscapGuiIntegrationReturn -Value $In | Should -BeLike $Like
        }
    }
}

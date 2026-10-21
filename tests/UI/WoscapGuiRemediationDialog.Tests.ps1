BeforeDiscovery {
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms
    $script:Plan = @(
        [pscustomobject]@{ StigId = 'R-1'; StigIds = @('R-1'); Title = 'Reg'; CheckType = 'Registry'; Action = 'Set HKLM:\S\A = 1 (dword)'; State = 'Planned'; Detail = '' }
        [pscustomobject]@{ StigId = 'A-1'; StigIds = @('A-1','A-2'); Title = 'Logon'; CheckType = 'AuditPolicy'; Action = "Enable audit 'Logon': success and failure"; State = 'Planned'; Detail = '' }
        [pscustomobject]@{ StigId = 'M-1'; StigIds = @('M-1'); Title = 'Svc'; CheckType = 'Service'; Action = 'Manual remediation required'; State = 'Manual'; Detail = 'no automation' }
    )
    $script:Manual = @($script:Plan[2])

    # Every visible control must sit inside its parent's client area.
    function Assert-InsideParent([System.Windows.Forms.Control] $Root) {
        foreach ($c in $Root.Controls) {
            if ($c.Visible) {
                $c.Left  | Should -BeGreaterOrEqual 0 -Because "$($c.GetType().Name) '$($c.Text)'"
                $c.Right | Should -BeLessOrEqual $c.Parent.ClientSize.Width -Because "$($c.GetType().Name) '$($c.Text)' R=$($c.Right) W=$($c.Parent.ClientSize.Width)"
            }
            Assert-InsideParent $c
        }
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Remediation confirmation dialog' -Skip:(-not $script:IsSta) {
    It 'ticks Planned rows, locks Manual rows, and returns the ticked rows'' StigIds' {
        InModuleScope woscap -Parameters @{ Plan = $script:Plan } {
            param($Plan)
            $d = New-WoscapGuiRemediationDialog -Plan $Plan -Summary '' -Elevated $true
            try {
                $g = $d.Tag['Grid']
                $g.Rows.Count | Should -Be 3
                $g.Rows[0].Cells[0].Value | Should -BeTrue
                $g.Rows[2].Cells[0].Value | Should -BeFalse
                $g.Rows[2].Cells[0].ReadOnly | Should -BeTrue
                @(Get-WoscapGuiRemediationSelection -Tag $d.Tag) | Should -Be @('R-1', 'A-1', 'A-2')
                $g.Rows[0].Cells[0].Value = $false
                @(Get-WoscapGuiRemediationSelection -Tag $d.Tag) | Should -Be @('A-1', 'A-2')
            } finally { $d.Dispose() }
        }
    }
    It 'never makes Apply the accept button, and Cancel is the cancel button' {
        InModuleScope woscap -Parameters @{ Plan = $script:Plan } {
            param($Plan)
            $d = New-WoscapGuiRemediationDialog -Plan $Plan -Summary '' -Elevated $true
            try {
                $d.AcceptButton | Should -BeNullOrEmpty
                $d.CancelButton | Should -Be $d.Tag['Cancel']
                $d.Tag['Apply'].DialogResult | Should -Be ([System.Windows.Forms.DialogResult]::OK)
            } finally { $d.Dispose() }
        }
    }
    It 'enables Apply only when elevated and something is ticked' -ForEach @(
        @{ Case = 'elevated, ticked';         Elevated = $true;  Untick = $false; Expect = $true }
        @{ Case = 'not elevated';             Elevated = $false; Untick = $false; Expect = $false }
        @{ Case = 'elevated, nothing ticked'; Elevated = $true;  Untick = $true;  Expect = $false }
    ) {
        InModuleScope woscap -Parameters @{ Plan = $script:Plan; Elevated = $Elevated; Untick = $Untick; Expect = $Expect } {
            param($Plan, $Elevated, $Untick, $Expect)
            $d = New-WoscapGuiRemediationDialog -Plan $Plan -Summary '' -Elevated $Elevated
            try {
                if ($Untick) {
                    foreach ($row in $d.Tag['Grid'].Rows) { if (-not $row.Cells[0].ReadOnly) { $row.Cells[0].Value = $false } }
                    Update-WoscapGuiRemediationApply -Tag $d.Tag
                }
                $d.Tag['Apply'].Enabled | Should -Be $Expect
                $d.Tag['ElevationNote'].Text | Should -Match 'administrator'
            } finally { $d.Dispose() }
        }
    }
    It 'disables Apply for a manual-only plan even when elevated' {
        InModuleScope woscap -Parameters @{ Plan = $script:Manual } {
            param($Plan)
            $d = New-WoscapGuiRemediationDialog -Plan $Plan -Summary '' -Elevated $true
            try { $d.Tag['Apply'].Enabled | Should -BeFalse } finally { $d.Dispose() }
        }
    }
    It 'states automatic and manual counts plus the summary in the header' {
        InModuleScope woscap -Parameters @{ Plan = $script:Plan } {
            param($Plan)
            $d = New-WoscapGuiRemediationDialog -Plan $Plan -Summary '1 remote finding skipped.' -Elevated $true
            try {
                $d.Tag['Header'].Text | Should -Match '2 fixes'
                $d.Tag['Header'].Text | Should -Match '1 require'
                $d.Tag['Header'].Text | Should -Match 'remote'
            } finally { $d.Dispose() }
        }
    }
    It 'keeps the header count in step with the ticked automatic rows' {
        InModuleScope woscap -Parameters @{ Plan = $script:Plan } {
            param($Plan)
            $d = New-WoscapGuiRemediationDialog -Plan $Plan -Summary 'note.' -Elevated $true
            try {
                $d.Tag['Grid'].Rows[0].Cells[0].Value = $false
                $d.Tag['Header'].Text | Should -Match '^1 fixes will change this computer\. 1 require'
                $d.Tag['Header'].Text | Should -Match 'note\.'
                $d.Tag['Grid'].Rows[1].Cells[0].Value = $false
                $d.Tag['Header'].Text | Should -Match '^0 fixes will'
                $d.Tag['Grid'].Rows[0].Cells[0].Value = $true
                $d.Tag['Header'].Text | Should -Match '^1 fixes will'
            } finally { $d.Dispose() }
        }
    }
    It 'says fixes would change the computer when not elevated' {
        InModuleScope woscap -Parameters @{ Plan = $script:Plan } {
            param($Plan)
            $d = New-WoscapGuiRemediationDialog -Plan $Plan -Summary '' -Elevated $false
            try {
                $d.Tag['Header'].Text | Should -Match '^2 fixes would change this computer'
                $d.Tag['Header'].Text | Should -Not -Match 'will'
            } finally { $d.Dispose() }
        }
    }
    # A long summary must wrap, not widen the layout and push the buttons off-screen.
    It 'keeps every control inside its parent when shown (<W>x<H>, <Case>)' -ForEach @(
        @{ W = 760; H = 460; Case = 'no summary';   Summary = '' }
        @{ W = 600; H = 360; Case = 'no summary';   Summary = '' }
        @{ W = 760; H = 460; Case = 'long summary'; Summary = ('3 remote findings skipped because remediation only runs on this computer. ' * 3) }
        @{ W = 600; H = 360; Case = 'long summary'; Summary = ('3 remote findings skipped because remediation only runs on this computer. ' * 3) }
    ) {
        # Built in module scope, asserted here: Assert-InsideParent is not visible inside InModuleScope.
        $d = InModuleScope woscap -Parameters @{ Plan = $script:Plan; Summary = $Summary } {
            param($Plan, $Summary)
            New-WoscapGuiRemediationDialog -Plan $Plan -Summary $Summary -Elevated $false
        }
        try {
            $d.Show(); $d.Size = New-Object System.Drawing.Size($W, $H); [System.Windows.Forms.Application]::DoEvents()
            Assert-InsideParent $d
        } finally { $d.Close(); $d.Dispose() }
    }
}

Describe 'Remediation report dialog' -Skip:(-not $script:IsSta) {
    It 'summarizes states and offers Re-scan / Close' {
        InModuleScope woscap {
            $res = @(
                [pscustomobject]@{ StigIds = @('R-1'); Title = 'r'; Action = 'a'; State = 'Applied'; After = 'NotAFinding'; Detail = '' }
                [pscustomobject]@{ StigIds = @('R-2'); Title = 'r'; Action = 'a'; State = 'Failed';  After = '-'; Detail = 'access denied' }
                [pscustomobject]@{ StigIds = @('M-1'); Title = 'm'; Action = 'a'; State = 'Manual';  After = '-'; Detail = 'x' }
            )
            $d = New-WoscapGuiRemediationReport -Result $res
            try {
                $d.Tag['Grid'].Rows.Count | Should -Be 3
                $d.Tag['Summary'].Text | Should -Match 'Applied: 1'
                $d.Tag['Summary'].Text | Should -Match 'Failed: 1'
                $d.Tag['Summary'].Text | Should -Match 'Manual: 1'
                $d.Tag['Rescan'].DialogResult | Should -Be ([System.Windows.Forms.DialogResult]::Retry)
                $d.CancelButton | Should -Be $d.Tag['Close']
            } finally { $d.Dispose() }
        }
    }
    It 'keeps every control inside its parent when shown' {
        $d = InModuleScope woscap {
            New-WoscapGuiRemediationReport -Result @([pscustomobject]@{ StigIds = @('R-1'); Title = 'r'; Action = 'a'; State = 'Applied'; After = 'NotAFinding'; Detail = '' })
        }
        try {
            $d.Show(); [System.Windows.Forms.Application]::DoEvents()
            Assert-InsideParent $d
        } finally { $d.Close(); $d.Dispose() }
    }
}

Describe 'Remediation report with a partial fix' -Skip:(-not $script:IsSta) {
    It 'counts PartiallyApplied separately' {
        InModuleScope woscap {
            $d = New-WoscapGuiRemediationReport -Result @(
                [pscustomobject]@{ StigIds = @('C-1'); Title = 'c'; Action = 'a; b'; State = 'PartiallyApplied'; After = 'Open'; Detail = 'Succeeded: a. Failed: b: x. Not attempted: none.' }
                [pscustomobject]@{ StigIds = @('R-1'); Title = 'r'; Action = 'a'; State = 'Applied'; After = 'NotAFinding'; Detail = '' })
            try {
                $d.Tag['Summary'].Text | Should -Match 'Applied: 1   Partially applied: 1   Failed: 0'
            } finally { $d.Dispose() }
        }
    }
}


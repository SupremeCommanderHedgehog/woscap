BeforeDiscovery {
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'

    # Action handler, the plugin that offers it, and the dialogs it shows in order.
    $script:Flows = @(
        @{ Handler = 'Invoke-WoscapGuiIntegrationImportTargets'; Plugin = 'Ansible'; Command = 'Import-WoscapIntegration'
           Hook = 'Get-Targets'; Dialogs = @('Source', 'Config') }
        @{ Handler = 'Invoke-WoscapGuiIntegrationImportFindings'; Plugin = 'OpenVAS'; Command = 'Import-WoscapIntegration'
           Hook = 'Import-Findings'; Dialogs = @('Source', 'Config') }
        @{ Handler = 'Invoke-WoscapGuiIntegrationRunScan'; Plugin = 'OpenVAS'; Command = 'Invoke-WoscapIntegration'
           Hook = 'Invoke-ExternalScan'; Dialogs = @('Config') }
        @{ Handler = 'Invoke-WoscapGuiIntegrationExportFindings'; Plugin = 'Zabbix'; Command = 'Export-WoscapIntegration'
           Hook = 'Export-Findings'; Dialogs = @('Config') }
        @{ Handler = 'Invoke-WoscapGuiIntegrationExportRemediation'; Plugin = 'Ansible'; Command = 'Export-WoscapIntegration'
           Hook = 'New-Remediation'; Dialogs = @('Config', 'Save') }
    )
    $script:CancelCases = foreach ($f in $script:Flows) {
        foreach ($d in $f.Dialogs) { $f + @{ CancelAt = $d } }
    }
    $script:BusyCases = foreach ($f in $script:Flows) {
        foreach ($b in 'Scan', 'Remediation', 'Content', 'Integration') { $f + @{ Busy = $b } }
    }
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms

    $script:Report = Join-Path $TestDrive 'report.xml'
    Set-Content -LiteralPath $script:Report -Value '<report/>'

    # Every test: no real modal, no network, no file dialog, no real integration cmdlet.
    function Set-IntegrationFlowMocks {
        InModuleScope woscap {
            Mock Show-WoscapGuiMessage { $script:shown.Add($Text) }
            Mock Get-WoscapGuiCredential { }
            Mock Get-WoscapGuiOpenPath { @() }
            Mock Get-WoscapGuiFolderPath { $null }
            Mock Get-WoscapGuiSavePath { $null }
            Mock Show-WoscapGuiConfigForm { $null }
            Mock Show-WoscapGuiIntegrationSourceDialog { $null }
            Mock Show-WoscapGuiIntegrationFindings { }
            Mock Show-WoscapGuiDownloadDialog { $null }
            Mock Show-WoscapGuiUpdateDialog { $null }
            Mock Show-WoscapGuiUpdateConfirmDialog { $false }
            Mock Show-WoscapGuiUpdateReport { }
            Mock Show-WoscapGuiRemoveDialog { $null }
            Mock Show-WoscapGuiDisaTermsDialog { $null }
            Mock Show-WoscapGuiRemediationDialog { $null }
            Mock Show-WoscapGuiRemediationReport { }
            Mock Get-WoscapBenchmark { }
            Mock Import-WoscapIntegration { throw 'Import-WoscapIntegration must never run in a GUI test' }
            Mock Invoke-WoscapIntegration { throw 'Invoke-WoscapIntegration must never run in a GUI test' }
            Mock Export-WoscapIntegration { throw 'Export-WoscapIntegration must never run in a GUI test' }
            Mock Invoke-WoscapGuiRun { throw 'an integration action must never start a scan' }
            # Records each start; the test decides how the job settles.
            Mock Invoke-WoscapGuiScan {
                $script:runs.Add(@{ Command = $Command; Params = $ScanParameters; Busy = Get-TestBusyState $script:form.Tag })
                if ($script:settle) { & $script:settle $OnSettled $OnError }
            }
        }
    }

    function New-IntegrationFlowForm([string] $PluginFolder) {
        InModuleScope woscap -Parameters @{ Folder = $PluginFolder } {
            param($Folder)
            $script:form = New-WoscapMainForm
            $script:runs = [System.Collections.Generic.List[object]]::new()
            $script:shown = [System.Collections.Generic.List[string]]::new()
            $script:settle = $null
            $script:none = [pscustomobject]@{ Kind = 'None'; Message = ''; Count = 0 }
            $script:failed = [pscustomobject]@{ Kind = 'Error'; Message = 'gvmd unreachable'; Count = 1 }
            if ($Folder) { $script:form.Tag['IntegrationPath'].Text = $Folder }
            Update-WoscapGuiIntegrationView -Tag $script:form.Tag

            function script:Get-TestBusyState([hashtable] $T) {
                $s = @{}
                foreach ($k in 'Run', 'Remediate', 'ContentDownload', 'ContentUpdate', 'ContentRemove', 'ContentUseForScan',
                               'IntegrationImportTargets', 'IntegrationImportFindings', 'IntegrationRunScan',
                               'IntegrationExportFindings', 'IntegrationExportRemediation') {
                    $s[$k] = [bool]$T[$k].Enabled
                    $s["Menu$k"] = [bool]$T["Menu$k"].Enabled
                }
                $s['Busy'] = $T['Busy']
                $s
            }
            function script:Select-TestPlugin([string] $Name) {
                $g = $script:form.Tag['IntegrationGrid']
                $g.ClearSelection()
                @($g.Rows | Where-Object { $_.Tag.Name -eq $Name })[0].Selected = $true
                Update-WoscapGuiIntegrationSelection -Tag $script:form.Tag
            }
            function script:Set-TestScanResults {
                $t = $script:form.Tag
                $t['Results'].Add([pscustomobject]@{ Host = 'srv1'; StigId = 'R-1'; RuleId = 'SV-1'; Status = 'Open'; Cci = @('CCI-1') })
                $t['Results'].Add([pscustomobject]@{ Host = 'srv2'; StigId = 'R-2'; RuleId = 'SV-2'; Status = 'NotAFinding'; Cci = @() })
                $t['ResultsContext'] = @{ Benchmark = 'Windows11'; ContentPath = '' }
                Set-WoscapGuiActionEnabled -Tag $t -Action Remediate -Enabled $true
            }
            # Dialog answers that let every flow run to the runner.
            function script:Set-TestDialogAnswers([string] $CancelAt) {
                $script:cfg = @{ Server = 'gvm.example.invalid'; Port = 9390 }
                if ($CancelAt -eq 'Source') { Mock Show-WoscapGuiIntegrationSourceDialog { $null } }
                else { Mock Show-WoscapGuiIntegrationSourceDialog { @{ Path = $script:report; Correlate = $false } } }
                if ($CancelAt -eq 'Config') { Mock Show-WoscapGuiConfigForm { $null } }
                else { Mock Show-WoscapGuiConfigForm { $script:cfg } }
                if ($CancelAt -eq 'Save') { Mock Get-WoscapGuiSavePath { $null } }
                else { Mock Get-WoscapGuiSavePath { 'C:\out\playbook.yml' } }
            }
            function script:Assert-TestIdle {
                $t = $script:form.Tag
                $t['Busy'] | Should -BeNullOrEmpty
                foreach ($k in 'Run', 'MenuRun', 'ContentDownload', 'ContentUpdate', 'MenuContentDownload', 'MenuContentUpdate') {
                    $t[$k].Enabled | Should -BeTrue -Because "$k must be restored after the integration job"
                }
            }
        }
        InModuleScope woscap -Parameters @{ Report = $script:Report } { param($Report) $script:report = $Report }
    }

    # A plugin folder whose single plugin offers every hook, for -PluginPath checks.
    function New-TestFullPlugin([string] $Root) {
        $dir = Join-Path $Root 'Full'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'plugin.psd1') -Value @"
@{ Name = 'Full'; Version = '1.0.0'; Implementation = 'implementation.ps1'
   Capabilities = @('Get-Targets', 'Import-Findings', 'Invoke-ExternalScan', 'Export-Findings', 'New-Remediation') }
"@
        Set-Content -LiteralPath (Join-Path $dir 'implementation.ps1') -Value @"
@{ 'Get-Targets' = { }; 'Import-Findings' = { }; 'Invoke-ExternalScan' = { }; 'Export-Findings' = { }; 'New-Remediation' = { } }
"@
        $Root
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Integration flows: cancel, refuse, busy' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach {
        Set-IntegrationFlowMocks
        New-IntegrationFlowForm
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It '<Handler> cancelled at the <CancelAt> dialog runs nothing and stays idle' -ForEach $script:CancelCases {
        InModuleScope woscap -Parameters @{ Handler = $Handler; Plugin = $Plugin; CancelAt = $CancelAt } {
            param($Handler, $Plugin, $CancelAt)
            Set-TestScanResults
            Select-TestPlugin $Plugin
            Set-TestDialogAnswers -CancelAt $CancelAt
            & $Handler -Tag $script:form.Tag
            $script:runs.Count | Should -Be 0
            Should -Invoke Import-WoscapIntegration -Times 0 -Exactly
            Should -Invoke Invoke-WoscapIntegration -Times 0 -Exactly
            Should -Invoke Export-WoscapIntegration -Times 0 -Exactly
            Assert-TestIdle
            $script:form.Tag['IntegrationImportTargets'].Enabled | Should -Be ($Plugin -in 'Ansible', 'Zabbix') -Because 'cancel restores the selection rules'
        }
    }

    It '<Handler> refuses while Busy is <Busy> and shows no dialog' -ForEach $script:BusyCases {
        InModuleScope woscap -Parameters @{ Handler = $Handler; Plugin = $Plugin; Busy = $Busy } {
            param($Handler, $Plugin, $Busy)
            Set-TestScanResults
            Select-TestPlugin $Plugin
            Set-TestDialogAnswers
            $script:form.Tag['Busy'] = $Busy
            & $Handler -Tag $script:form.Tag
            $script:runs.Count | Should -Be 0
            Should -Invoke Show-WoscapGuiConfigForm -Times 0 -Exactly
            Should -Invoke Show-WoscapGuiIntegrationSourceDialog -Times 0 -Exactly
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Match 'running'
            $script:form.Tag['Busy'] | Should -Be $Busy
        }
    }

    It '<Handler> disables every gated action while its job runs' -ForEach $script:Flows {
        InModuleScope woscap -Parameters @{ Handler = $Handler; Plugin = $Plugin } {
            param($Handler, $Plugin)
            Set-TestScanResults
            Select-TestPlugin $Plugin
            Set-TestDialogAnswers
            & $Handler -Tag $script:form.Tag
            $script:runs.Count | Should -Be 1
            $state = $script:runs[0].Busy
            $state['Busy'] | Should -Be 'Integration'
            foreach ($k in @($state.Keys | Where-Object { $_ -ne 'Busy' })) {
                $state[$k] | Should -BeFalse -Because "$k must be disabled while the integration job runs"
            }
        }
    }

    It '<Handler> restores the UI after success' -ForEach $script:Flows {
        InModuleScope woscap -Parameters @{ Handler = $Handler; Plugin = $Plugin } {
            param($Handler, $Plugin)
            Set-TestScanResults
            Select-TestPlugin $Plugin
            Set-TestDialogAnswers
            $script:settle = { param($OnSettled, $OnError) & $OnSettled -Results @('srv9') -Outcome $script:none }
            & $Handler -Tag $script:form.Tag
            Assert-TestIdle
            $script:form.Tag['Remediate'].Enabled | Should -BeTrue -Because 'the scan results are still remediable'
        }
    }

    It '<Handler> restores the UI and reports the error once after a failed job' -ForEach $script:Flows {
        InModuleScope woscap -Parameters @{ Handler = $Handler; Plugin = $Plugin } {
            param($Handler, $Plugin)
            Set-TestScanResults
            Select-TestPlugin $Plugin
            Set-TestDialogAnswers
            $script:settle = {
                param($OnSettled, $OnError)
                & $OnError -Message 'gvmd unreachable'
                & $OnSettled -Results @() -Outcome $script:failed
            }
            $script:form.Tag['Tabs'].SelectedTab = $script:form.Tag['IntegrationsTab']
            & $Handler -Tag $script:form.Tag
            Assert-TestIdle
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Match 'failed: gvmd unreachable'
            $script:shown[0] | Should -Not -Match 'follow-up'
            Should -Invoke Show-WoscapGuiIntegrationFindings -Times 0 -Exactly
            $script:form.Tag['Tabs'].SelectedTab | Should -Not -Be $script:form.Tag['ScanTab']
        }
    }

    It '<Handler> restores the UI when the background job cannot start' -ForEach $script:Flows {
        InModuleScope woscap -Parameters @{ Handler = $Handler; Plugin = $Plugin } {
            param($Handler, $Plugin)
            Set-TestScanResults
            Select-TestPlugin $Plugin
            Set-TestDialogAnswers
            $script:settle = { throw 'runspace exploded' }
            & $Handler -Tag $script:form.Tag
            Assert-TestIdle
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Match 'runspace exploded'
        }
    }

    It '<Handler> reports a follow-up failure after success as completed, not failed' -ForEach $script:Flows {
        InModuleScope woscap -Parameters @{ Handler = $Handler; Plugin = $Plugin } {
            param($Handler, $Plugin)
            Set-TestScanResults
            Select-TestPlugin $Plugin
            Set-TestDialogAnswers
            # Every flow's follow-up shows something; make that step throw, as the runner's tick catch would see it.
            Mock Show-WoscapGuiIntegrationFindings { throw 'dialog broke' }
            Mock Show-WoscapGuiMessage {
                if ($Text -notmatch 'follow-up') { throw 'dialog broke' }
                $script:shown.Add($Text)
            }
            # Import targets' follow-up writes the Scan tab; make that step throw too.
            Mock Set-WoscapGuiIntegrationTargets { throw 'dialog broke' }
            $script:settle = {
                param($OnSettled, $OnError)
                try { & $OnSettled -Results @('srv9') -Outcome $script:none } catch { & $OnError -Message $_.Exception.Message }
            }
            & $Handler -Tag $script:form.Tag
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Match 'completed, but a follow-up step failed: dialog broke'
            $script:form.Tag['IntegrationStatus'].Text | Should -Match 'follow-up step failed'
            $script:form.Tag['Busy'] | Should -BeNullOrEmpty
        }
    }

    It '<Handler> never shows a credential or secret in any message or status line' -ForEach $script:Flows {
        InModuleScope woscap -Parameters @{ Handler = $Handler; Plugin = $Plugin } {
            param($Handler, $Plugin)
            Set-TestScanResults
            Select-TestPlugin $Plugin
            Set-TestDialogAnswers
            $pw = ConvertTo-SecureString 'Pa55-w0rd-XYZ' -AsPlainText -Force
            $script:cfg['Credential'] = New-Object System.Management.Automation.PSCredential('gvmadmin-USER', $pw)
            $script:cfg['Token'] = 'tok-SECRET-123'
            foreach ($settle in @(
                { param($OnSettled, $OnError) & $OnSettled -Results @('srv9', [pscustomobject]@{ FactsPath = 'C:\f.json' }) -Outcome $script:none },
                { param($OnSettled, $OnError) & $OnError -Message 'boom'; & $OnSettled -Results @() -Outcome $script:failed },
                { throw 'cannot start' })) {
                $script:settle = $settle
                & $Handler -Tag $script:form.Tag
                $texts = @($script:shown) + @($script:form.Tag['IntegrationStatus'].Text, $script:form.Tag['Status'].Text)
                foreach ($x in $texts) {
                    $x | Should -Not -Match 'Pa55-w0rd-XYZ'
                    $x | Should -Not -Match 'tok-SECRET-123'
                    $x | Should -Not -Match 'gvmadmin-USER'
                }
            }
            $script:runs.Count | Should -Be 3
        }
    }
}

Describe 'Integration flows: what reaches the cmdlet' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach { Set-IntegrationFlowMocks }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It '<Handler> passes exactly the form hashtable as -Config and the bundled plugin''s own folder as -PluginPath' -ForEach $script:Flows {
        New-IntegrationFlowForm
        InModuleScope woscap -Parameters @{ Handler = $Handler; Plugin = $Plugin; Command = $Command } {
            param($Handler, $Plugin, $Command)
            Set-TestScanResults
            Select-TestPlugin $Plugin
            Set-TestDialogAnswers
            & $Handler -Tag $script:form.Tag
            $script:runs.Count | Should -Be 1
            $script:runs[0].Command | Should -Be $Command
            $p = $script:runs[0].Params
            [object]::ReferenceEquals($p['Config'], $script:cfg) | Should -BeTrue -Because 'Config must be the form hashtable itself'
            @($p['Config'].Keys | Sort-Object) | Should -Be @('Port', 'Server')
            $p['Integration'] | Should -Be $Plugin
            $p['PluginPath'] | Should -Be (Join-Path (Get-WoscapPluginRoot) $Plugin)
        }
    }

    It '<Handler> passes the plugin''s own folder as -PluginPath from a Plugin folder' -ForEach $script:Flows {
        $root = New-TestFullPlugin (Join-Path $TestDrive ('plugins-' + [guid]::NewGuid().ToString('N')))
        New-IntegrationFlowForm -PluginFolder $root
        InModuleScope woscap -Parameters @{ Handler = $Handler; Root = $root } {
            param($Handler, $Root)
            Set-TestScanResults
            Select-TestPlugin 'Full'
            Set-TestDialogAnswers
            & $Handler -Tag $script:form.Tag
            $p = $script:runs[0].Params
            $p['Integration'] | Should -Be 'Full'
            $p['PluginPath'] | Should -Be (Join-Path $Root 'Full')
            [object]::ReferenceEquals($p['Config'], $script:cfg) | Should -BeTrue
        }
    }

    It 'asks the config form for the options of the hook being run' -ForEach $script:Flows {
        New-IntegrationFlowForm
        InModuleScope woscap -Parameters @{ Handler = $Handler; Plugin = $Plugin; Hook = $Hook } {
            param($Handler, $Plugin, $Hook)
            Set-TestScanResults
            Select-TestPlugin $Plugin
            Set-TestDialogAnswers
            $script:formOptions = 'unset'
            Mock Show-WoscapGuiConfigForm { $script:formOptions = $Options; $script:formTitle = $Title; $script:cfg }
            & $Handler -Tag $script:form.Tag
            $pluginRow = @($script:form.Tag['IntegrationGrid'].Rows | Where-Object { $_.Tag.Name -eq $Plugin })[0].Tag
            $want = @(Get-WoscapGuiConfigOptions -Plugin $pluginRow -Hook $Hook | ForEach-Object { $_.Name })
            @($script:formOptions | ForEach-Object { $_.Name }) | Should -Be $want
            $script:formTitle | Should -Match $Plugin
        }
    }

    It 'refuses a Plugin folder edited since the listing before any dialog' -ForEach $script:Flows {
        New-IntegrationFlowForm
        InModuleScope woscap -Parameters @{ Handler = $Handler; Plugin = $Plugin } {
            param($Handler, $Plugin)
            Set-TestScanResults
            Select-TestPlugin $Plugin
            Set-TestDialogAnswers
            $script:form.Tag['IntegrationPath'].Text = 'C:\somewhere\else'
            & $Handler -Tag $script:form.Tag
            $script:runs.Count | Should -Be 0
            Should -Invoke Show-WoscapGuiConfigForm -Times 0 -Exactly
            $script:shown[0] | Should -Match 'Refresh'
        }
    }
}

Describe 'Import targets' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach {
        Set-IntegrationFlowMocks
        New-IntegrationFlowForm
        InModuleScope woscap { Select-TestPlugin 'Ansible'; Set-TestDialogAnswers }
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'passes -Targets and the chosen -Source' {
        InModuleScope woscap {
            Invoke-WoscapGuiIntegrationImportTargets -Tag $script:form.Tag
            $p = $script:runs[0].Params
            @($p.Keys | Sort-Object) | Should -Be @('Config', 'Integration', 'PluginPath', 'Source', 'Targets')
            $p['Targets'] | Should -BeTrue
            $p['Source'] | Should -Be $script:report
        }
    }

    It 'omits -Source when none was chosen' {
        InModuleScope woscap {
            Mock Show-WoscapGuiIntegrationSourceDialog { @{ Path = ''; Correlate = $false } }
            Invoke-WoscapGuiIntegrationImportTargets -Tag $script:form.Tag
            $script:runs[0].Params.ContainsKey('Source') | Should -BeFalse
        }
    }

    It 'writes exactly the returned hosts into Scan Targets, switches to the Scan tab and never scans' {
        InModuleScope woscap {
            $script:form.Tag['Targets'].Text = 'old-host'
            $script:settle = { param($OnSettled, $OnError) & $OnSettled -Results @('web01', 'db02.corp.local', '10.0.0.7') -Outcome $script:none }
            Invoke-WoscapGuiIntegrationImportTargets -Tag $script:form.Tag
            $script:form.Tag['Targets'].Text | Should -BeExactly 'web01, db02.corp.local, 10.0.0.7'
            $script:form.Tag['Tabs'].SelectedTab | Should -Be $script:form.Tag['ScanTab']
            $script:form.Tag['Status'].Text | Should -Match '3 target'
            Should -Invoke Invoke-WoscapGuiRun -Times 0 -Exactly
            $script:runs.Count | Should -Be 1
            $script:runs[0].Command | Should -Be 'Import-WoscapIntegration'
            ConvertTo-WoscapGuiScanParameter -XccdfPath 'x' -Benchmark 'b' -Targets $script:form.Tag['Targets'].Text |
                ForEach-Object { @($_['ComputerName']) } | Should -Be @('web01', 'db02.corp.local', '10.0.0.7')
        }
    }

    It 'leaves Scan Targets and the tab alone when no hosts come back' {
        InModuleScope woscap {
            $script:form.Tag['Targets'].Text = 'old-host'
            $script:form.Tag['Tabs'].SelectedTab = $script:form.Tag['IntegrationsTab']
            $script:settle = { param($OnSettled, $OnError) & $OnSettled -Results @('', $null) -Outcome $script:none }
            Invoke-WoscapGuiIntegrationImportTargets -Tag $script:form.Tag
            $script:form.Tag['Targets'].Text | Should -Be 'old-host'
            $script:form.Tag['Tabs'].SelectedTab | Should -Be $script:form.Tag['IntegrationsTab']
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Match 'no targets'
            Assert-TestIdle
        }
    }

    It 'keeps the hosts and notes the warnings of a partial import' {
        InModuleScope woscap {
            $script:settle = {
                param($OnSettled, $OnError)
                & $OnSettled -Results @('web01') -Outcome ([pscustomobject]@{ Kind = 'Warning'; Message = 'group x empty'; Count = 1 })
            }
            Invoke-WoscapGuiIntegrationImportTargets -Tag $script:form.Tag
            $script:form.Tag['Targets'].Text | Should -Be 'web01'
            $script:form.Tag['IntegrationStatus'].Text | Should -Match '1 warning'
        }
    }
}

Describe 'Import findings' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach {
        Set-IntegrationFlowMocks
        New-IntegrationFlowForm
        InModuleScope woscap {
            Select-TestPlugin 'OpenVAS'; Set-TestDialogAnswers
            $script:findings = @([pscustomobject]@{ Host = 'srv1'; Id = 'f1'; Cve = @('CVE-1') }, [pscustomobject]@{ Host = 'srv2'; Id = 'f2'; Cve = @() })
        }
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'passes -Findings -Path and no -CorrelateWith when the box was not ticked' {
        InModuleScope woscap {
            Set-TestScanResults
            Invoke-WoscapGuiIntegrationImportFindings -Tag $script:form.Tag
            $p = $script:runs[0].Params
            @($p.Keys | Sort-Object) | Should -Be @('Config', 'Findings', 'Integration', 'Path', 'PluginPath')
            $p['Findings'] | Should -BeTrue
            $p['Path'] | Should -Be $script:report
        }
    }

    It 'passes exactly the current scan results as -CorrelateWith when the box was ticked' {
        InModuleScope woscap {
            Set-TestScanResults
            Mock Show-WoscapGuiIntegrationSourceDialog { @{ Path = $script:report; Correlate = $true } }
            Invoke-WoscapGuiIntegrationImportFindings -Tag $script:form.Tag
            $c = @($script:runs[0].Params['CorrelateWith'])
            $c.Count | Should -Be 2
            for ($i = 0; $i -lt 2; $i++) {
                [object]::ReferenceEquals($c[$i], $script:form.Tag['Results'][$i]) | Should -BeTrue
            }
        }
    }

    It 'offers correlation in the source dialog only when there are scan results' {
        InModuleScope woscap {
            $script:settle = { param($OnSettled, $OnError) & $OnSettled -Results @() -Outcome $script:none }
            Invoke-WoscapGuiIntegrationImportFindings -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiIntegrationSourceDialog -Times 1 -Exactly -ParameterFilter { -not $CanCorrelate }
            Set-TestScanResults
            Invoke-WoscapGuiIntegrationImportFindings -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiIntegrationSourceDialog -Times 1 -Exactly -ParameterFilter { $CanCorrelate }
        }
    }

    It 'refuses correlation when there are no current scan results' {
        InModuleScope woscap {
            Mock Show-WoscapGuiIntegrationSourceDialog { @{ Path = $script:report; Correlate = $true } }
            Invoke-WoscapGuiIntegrationImportFindings -Tag $script:form.Tag
            $script:runs.Count | Should -Be 0
            Should -Invoke Show-WoscapGuiConfigForm -Times 0 -Exactly
            $script:shown[0] | Should -Match 'scan results'
            Assert-TestIdle
        }
    }

    It 'shows the imported findings without links when not correlated' {
        InModuleScope woscap {
            $script:settle = { param($OnSettled, $OnError) & $OnSettled -Results $script:findings -Outcome $script:none }
            Mock Show-WoscapGuiIntegrationFindings { $script:dlg = @{ Findings = $Findings; Links = $Links } }
            Invoke-WoscapGuiIntegrationImportFindings -Tag $script:form.Tag
            @($script:dlg.Findings).Count | Should -Be 2
            $script:dlg.Links | Should -BeNullOrEmpty
            $script:form.Tag['IntegrationStatus'].Text | Should -Match '2 finding'
        }
    }

    It 'shows findings and links when correlated' {
        InModuleScope woscap {
            Set-TestScanResults
            Mock Show-WoscapGuiIntegrationSourceDialog { @{ Path = $script:report; Correlate = $true } }
            $script:joined = [pscustomobject]@{ Results = @(); Findings = $script:findings
                Links = @([pscustomobject]@{ Host = 'srv1'; RuleId = 'SV-1'; FindingId = 'f1'; MatchedOn = 'CVE-1' }) }
            $script:settle = { param($OnSettled, $OnError) & $OnSettled -Results @($script:joined) -Outcome $script:none }
            Mock Show-WoscapGuiIntegrationFindings { $script:dlg = @{ Findings = $Findings; Links = $Links } }
            Invoke-WoscapGuiIntegrationImportFindings -Tag $script:form.Tag
            @($script:dlg.Findings).Count | Should -Be 2
            @($script:dlg.Links).Count | Should -Be 1
            $script:form.Tag['IntegrationStatus'].Text | Should -Match '1 link'
        }
    }
}

Describe 'Run external scan' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach {
        Set-IntegrationFlowMocks
        New-IntegrationFlowForm
        InModuleScope woscap { Select-TestPlugin 'OpenVAS'; Set-TestDialogAnswers }
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'runs Invoke-WoscapIntegration with only Integration and Config, then shows the findings' {
        InModuleScope woscap {
            $script:settle = { param($OnSettled, $OnError) & $OnSettled -Results @([pscustomobject]@{ Host = 'h'; Id = 'x' }) -Outcome $script:none }
            Mock Show-WoscapGuiIntegrationFindings { $script:dlg = @{ Findings = $Findings; Links = $Links } }
            Invoke-WoscapGuiIntegrationRunScan -Tag $script:form.Tag
            @($script:runs[0].Params.Keys | Sort-Object) | Should -Be @('Config', 'Integration', 'PluginPath')
            @($script:dlg.Findings).Count | Should -Be 1
            $script:dlg.Links | Should -BeNullOrEmpty
        }
    }

    It 'never needs scan results' {
        InModuleScope woscap {
            Invoke-WoscapGuiIntegrationRunScan -Tag $script:form.Tag
            $script:runs.Count | Should -Be 1
        }
    }
}

Describe 'Export findings and remediation' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach {
        Set-IntegrationFlowMocks
        New-IntegrationFlowForm
        InModuleScope woscap { Set-TestDialogAnswers }
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It '<Handler> refuses with no current scan results before any dialog' -ForEach @(
        @{ Handler = 'Invoke-WoscapGuiIntegrationExportFindings'; Plugin = 'Zabbix' }
        @{ Handler = 'Invoke-WoscapGuiIntegrationExportRemediation'; Plugin = 'Ansible' }
    ) {
        InModuleScope woscap -Parameters @{ Handler = $Handler; Plugin = $Plugin } {
            param($Handler, $Plugin)
            Select-TestPlugin $Plugin
            & $Handler -Tag $script:form.Tag
            $script:runs.Count | Should -Be 0
            Should -Invoke Show-WoscapGuiConfigForm -Times 0 -Exactly
            Should -Invoke Get-WoscapGuiSavePath -Times 0 -Exactly
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Match 'scan results'
            Assert-TestIdle
        }
    }

    It 'Export findings passes exactly the current results and reports the hook return' {
        InModuleScope woscap {
            Set-TestScanResults
            Select-TestPlugin 'Ansible'
            $script:settle = { param($OnSettled, $OnError) & $OnSettled -Results @([pscustomobject]@{ FactsPath = 'C:\t\facts.json'; Count = 2 }) -Outcome $script:none }
            Invoke-WoscapGuiIntegrationExportFindings -Tag $script:form.Tag
            $p = $script:runs[0].Params
            @($p.Keys | Sort-Object) | Should -Be @('Config', 'Integration', 'PluginPath', 'Result')
            $r = @($p['Result'])
            $r.Count | Should -Be 2
            for ($i = 0; $i -lt 2; $i++) { [object]::ReferenceEquals($r[$i], $script:form.Tag['Results'][$i]) | Should -BeTrue }
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Match 'Exported 2 result'
            $script:shown[0] | Should -Match 'FactsPath=C:\\t\\facts.json'
        }
    }

    It 'Export findings says so when the integration reports failure' {
        InModuleScope woscap {
            Set-TestScanResults
            Select-TestPlugin 'Zabbix'
            $script:settle = { param($OnSettled, $OnError) & $OnSettled -Results @($false) -Outcome $script:none }
            Invoke-WoscapGuiIntegrationExportFindings -Tag $script:form.Tag
            $script:shown[0] | Should -Match 'did not succeed'
            $script:form.Tag['IntegrationStatus'].Text | Should -Match 'did not succeed'
        }
    }

    It 'Export remediation passes the current results, -Remediation and the chosen path, then shows the path' {
        InModuleScope woscap {
            Set-TestScanResults
            Select-TestPlugin 'Ansible'
            $script:settle = { param($OnSettled, $OnError) & $OnSettled -Results @('C:\out\playbook.yml') -Outcome $script:none }
            Invoke-WoscapGuiIntegrationExportRemediation -Tag $script:form.Tag
            Should -Invoke Get-WoscapGuiSavePath -Times 1 -Exactly -ParameterFilter { $Format -eq 'yml' }
            $p = $script:runs[0].Params
            @($p.Keys | Sort-Object) | Should -Be @('Config', 'Integration', 'Path', 'PluginPath', 'Remediation', 'Result')
            $p['Remediation'] | Should -BeTrue
            $p['Path'] | Should -Be 'C:\out\playbook.yml'
            $r = @($p['Result'])
            $r.Count | Should -Be 2
            for ($i = 0; $i -lt 2; $i++) { [object]::ReferenceEquals($r[$i], $script:form.Tag['Results'][$i]) | Should -BeTrue }
            $script:form.Tag['IntegrationStatus'].Text | Should -Match ([regex]::Escape('C:\out\playbook.yml'))
            $script:shown[0] | Should -Match ([regex]::Escape('C:\out\playbook.yml'))
        }
    }
}

Describe 'Integration action wiring' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach {
        Set-IntegrationFlowMocks
        New-IntegrationFlowForm
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'button and menu item both call <Handler>' -ForEach @(
        @{ Key = 'IntegrationImportTargets'; Handler = 'Invoke-WoscapGuiIntegrationImportTargets' }
        @{ Key = 'IntegrationImportFindings'; Handler = 'Invoke-WoscapGuiIntegrationImportFindings' }
        @{ Key = 'IntegrationRunScan'; Handler = 'Invoke-WoscapGuiIntegrationRunScan' }
        @{ Key = 'IntegrationExportFindings'; Handler = 'Invoke-WoscapGuiIntegrationExportFindings' }
        @{ Key = 'IntegrationExportRemediation'; Handler = 'Invoke-WoscapGuiIntegrationExportRemediation' }
    ) {
        InModuleScope woscap -Parameters @{ Key = $Key; Handler = $Handler } {
            param($Key, $Handler)
            Mock $Handler { }
            $t = $script:form.Tag
            Set-WoscapGuiActionEnabled -Tag $t -Action $Key -Enabled $true
            $m = [System.Windows.Forms.Button].GetMethod('OnClick', [System.Reflection.BindingFlags]'Instance, NonPublic')
            [void]$m.Invoke($t[$Key], @([System.EventArgs]::Empty))
            $t["Menu$Key"].PerformClick()
            Should -Invoke $Handler -Times 2 -Exactly
        }
    }
}

Describe 'Integration flows: review fixes' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach { Set-IntegrationFlowMocks }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'passes the listed folder as -PluginPath when the folder name differs from the manifest Name' {
        $root = Join-Path $TestDrive ('renamed-' + [guid]::NewGuid().ToString('N'))
        $dir = Join-Path $root 'OpenVAS-v2'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'plugin.psd1') -Value "@{ Name = 'Fake'; Version = '1.0.0'; Capabilities = @('Invoke-ExternalScan'); Implementation = 'implementation.ps1' }"
        Set-Content -LiteralPath (Join-Path $dir 'implementation.ps1') -Value "@{ 'Invoke-ExternalScan' = { } }"
        New-IntegrationFlowForm -PluginFolder $root
        InModuleScope woscap -Parameters @{ Dir = $dir } {
            param($Dir)
            Select-TestPlugin 'Fake'
            Set-TestDialogAnswers
            Invoke-WoscapGuiIntegrationRunScan -Tag $script:form.Tag
            $p = $script:runs[0].Params
            $p['Integration'] | Should -Be 'Fake'
            $p['PluginPath'] | Should -Be $Dir
        }
    }

    It 'refuses a plugin whose ConfigOptions schema is invalid, listing the errors, without building the form' {
        $root = Join-Path $TestDrive ('badschema-' + [guid]::NewGuid().ToString('N'))
        $dir = Join-Path $root 'Bad'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $manifest = @(
            "@{ Name = 'Bad'; Version = '1.0.0'; Capabilities = @('Invoke-ExternalScan'); Implementation = 'implementation.ps1'"
            "   ConfigOptions = @( @{ Name = 'Port'; Type = 'Number'; Default = 1.5; Hooks = @('Invoke-ExternalScan') }"
            "                      @{ Name = 'Mode'; Type = 'Blob'; Hooks = @('Invoke-ExternalScan') } ) }"
        )
        Set-Content -LiteralPath (Join-Path $dir 'plugin.psd1') -Value $manifest
        Set-Content -LiteralPath (Join-Path $dir 'implementation.ps1') -Value "@{ 'Invoke-ExternalScan' = { } }"
        New-IntegrationFlowForm -PluginFolder $root
        InModuleScope woscap {
            Select-TestPlugin 'Bad'
            Set-TestDialogAnswers
            { Invoke-WoscapGuiIntegrationRunScan -Tag $script:form.Tag } | Should -Not -Throw
            Should -Invoke Show-WoscapGuiConfigForm -Times 0 -Exactly
            $script:runs.Count | Should -Be 0
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Match "'Port' Default"
            $script:shown[0] | Should -Match "'Mode'"
            Assert-TestIdle
        }
    }

    It 'reports a config form that fails to build instead of letting it escape the handler' {
        New-IntegrationFlowForm
        InModuleScope woscap {
            Select-TestPlugin 'OpenVAS'
            Set-TestDialogAnswers
            Mock Show-WoscapGuiConfigForm { throw 'form exploded' }
            { Invoke-WoscapGuiIntegrationRunScan -Tag $script:form.Tag } | Should -Not -Throw
            $script:runs.Count | Should -Be 0
            $script:shown[0] | Should -Match 'form exploded'
            Assert-TestIdle
        }
    }

    It '<Handler> refuses stale results (after a remediation) before any dialog' -ForEach @(
        @{ Handler = 'Invoke-WoscapGuiIntegrationExportFindings'; Plugin = 'Zabbix' }
        @{ Handler = 'Invoke-WoscapGuiIntegrationExportRemediation'; Plugin = 'Ansible' }
    ) {
        New-IntegrationFlowForm
        InModuleScope woscap -Parameters @{ Handler = $Handler; Plugin = $Plugin } {
            param($Handler, $Plugin)
            Set-TestScanResults
            $script:form.Tag['ResultsStale'] = $true
            Select-TestPlugin $Plugin
            Set-TestDialogAnswers
            & $Handler -Tag $script:form.Tag
            $script:runs.Count | Should -Be 0
            Should -Invoke Show-WoscapGuiConfigForm -Times 0 -Exactly
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Match 'predate'
            $script:shown[0] | Should -Match 're-scan'
        }
    }

    It '<Handler> shows the warning text of a partial run, not just a count' -ForEach $script:Flows {
        New-IntegrationFlowForm
        InModuleScope woscap -Parameters @{ Handler = $Handler; Plugin = $Plugin } {
            param($Handler, $Plugin)
            Set-TestScanResults
            Select-TestPlugin $Plugin
            Set-TestDialogAnswers
            $script:settle = {
                param($OnSettled, $OnError)
                & $OnSettled -Results @('srv9') -Outcome ([pscustomobject]@{ Kind = 'Warning'; Message = 'woscap: host 10.9.9.9 skipped'; Count = 1 })
            }
            & $Handler -Tag $script:form.Tag
            $t = $script:form.Tag
            $t['StatusTip'].GetToolTip($t['IntegrationStatus']) | Should -Match 'host 10\.9\.9\.9 skipped'
            $t['IntegrationStatus'].Text | Should -Match '1 warning'
        }
    }

    It 'clears the previous warning tooltip when the next job starts' {
        New-IntegrationFlowForm
        InModuleScope woscap {
            Select-TestPlugin 'OpenVAS'
            Set-TestDialogAnswers
            $script:settle = { param($OnSettled, $OnError) & $OnSettled -Results @('x') -Outcome ([pscustomobject]@{ Kind = 'Warning'; Message = 'old warning'; Count = 1 }) }
            Invoke-WoscapGuiIntegrationRunScan -Tag $script:form.Tag
            $script:settle = { param($OnSettled, $OnError) & $OnSettled -Results @('x') -Outcome $script:none }
            Invoke-WoscapGuiIntegrationRunScan -Tag $script:form.Tag
            $t = $script:form.Tag
            $t['StatusTip'].GetToolTip($t['IntegrationStatus']) | Should -BeNullOrEmpty
        }
    }
}

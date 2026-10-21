BeforeDiscovery {
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
}
BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms

    # Same layout as tests/UI/New-WoscapGuiContentTab.Tests.ps1: <root>\<bench>\<rev>\*_Manual-xccdf.xml + sidecar.
    function Add-TestRevision([string] $Root, [string] $Bench, [string] $Rev, [string] $Hash, [string] $Title) {
        $rd = Join-Path (Join-Path $Root $Bench) $Rev
        New-Item -ItemType Directory -Path $rd -Force | Out-Null
        $xccdf = Join-Path $rd ("U_{0}_Manual-xccdf.xml" -f $Bench)
        Set-Content -LiteralPath $xccdf -Value '<Benchmark/>'
        $sidecar = InModuleScope woscap -Parameters @{ Rd = $rd } { param($Rd) Get-WoscapContentSidecarPath -RevisionDir $Rd }
        Set-Content -LiteralPath $sidecar -Value (@{
            benchmark = $Bench; revision = $Rev; contentSha256 = $Hash; title = $Title
            sourceUrl = "https://example.invalid/$Bench.zip"
        } | ConvertTo-Json)
        $xccdf
    }
    function New-TestCache([string] $Root) {
        $null = Add-TestRevision -Root $Root -Bench 'Windows11' -Rev 'V1R5' -Hash ('A' * 64) -Title 'Windows 11 STIG'
        $null = Add-TestRevision -Root $Root -Bench 'Windows11' -Rev 'V1R6' -Hash ('B' * 64) -Title 'Windows 11 STIG'
        $null = Add-TestRevision -Root $Root -Bench 'Edge' -Rev 'V2R1' -Hash ('C' * 64) -Title 'Edge STIG'
        $Root
    }

    # Every test: no real modal, no network, no real cache, no marker write.
    function Set-ContentFlowMocks([switch] $RealRun) {
        Mock -ModuleName woscap Show-WoscapGuiMessage { }
        Mock -ModuleName woscap Show-WoscapGuiDownloadDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiUpdateDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiUpdateConfirmDialog { $false }
        Mock -ModuleName woscap Show-WoscapGuiUpdateReport { }
        Mock -ModuleName woscap Show-WoscapGuiRemoveDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiDisaTermsDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiRemediationDialog { $null }
        Mock -ModuleName woscap Show-WoscapGuiRemediationReport { }
        Mock -ModuleName woscap Get-WoscapGuiFolderPath { $null }
        Mock -ModuleName woscap Get-WoscapGuiOpenPath { $null }
        Mock -ModuleName woscap Write-WoscapDisaTermsMarker { }
        Mock -ModuleName woscap Save-WoscapStigContent { throw 'Save-WoscapStigContent must never run in a GUI test' }
        Mock -ModuleName woscap Update-WoscapBenchmark { throw 'Update-WoscapBenchmark must never run in a GUI test' }
        Mock -ModuleName woscap Invoke-WoscapGuiScan { }
        if (-not $RealRun) { Mock -ModuleName woscap Invoke-WoscapGuiRun { $false } }
        Mock -ModuleName woscap Resolve-WoscapGuiDisaTerms { @{ Proceed = $true; AcceptSwitch = $false; Remember = $false } }
        Mock -ModuleName woscap Get-WoscapBenchmark {
            if ([string]::IsNullOrWhiteSpace($Destination)) { throw 'test tried to list the real content cache' }
            $splat = @{ Destination = $Destination }
            if ($Benchmark) { $splat['Benchmark'] = $Benchmark }
            & (Get-Item -LiteralPath function:Get-WoscapBenchmark) @splat
        }
        Mock -ModuleName woscap Remove-WoscapBenchmark {
            if ([string]::IsNullOrWhiteSpace($Destination)) { throw 'test tried to remove from the real content cache' }
            'removed'
        }
    }

    function New-ContentFlowForm([string] $Cache) {
        InModuleScope woscap -Parameters @{ Cache = $Cache } {
            param($Cache)
            $script:form = New-WoscapMainForm
            $script:form.Tag['ContentDestination'].Text = $Cache
            $script:none  = [pscustomobject]@{ Kind = 'None'; Message = ''; Count = 0 }
            $script:failed = [pscustomobject]@{ Kind = 'Error'; Message = 'boom'; Count = 1 }
            $script:runs = [System.Collections.Generic.List[object]]::new()
            # Enabled state of every busy-gated control, captured when a background job starts.
            function script:Get-TestBusyState([hashtable] $T) {
                $s = @{}
                foreach ($k in 'ContentDownload','ContentUpdate','ContentRemove','ContentUseForScan','Run','Remediate',
                               'MenuContentDownload','MenuContentUpdate','MenuContentRemove','MenuContentUseForScan','MenuRun','MenuRemediate') {
                    $s[$k] = [bool]$T[$k].Enabled
                }
                $s
            }
            function script:Select-TestRow([hashtable] $T, [string] $Bench, [string] $Rev) {
                $g = $T['ContentGrid']
                $g.ClearSelection()
                $row = @($g.Rows | Where-Object { $_.Tag.Benchmark -eq $Bench -and $_.Tag.Revision -eq $Rev })[0]
                $row.Selected = $true
                Update-WoscapGuiContentSelection -Tag $T
                $row
            }
            # A stand-in for a completed scan so Remediate restoration can be observed.
            function script:Set-TestScanResults([hashtable] $T, [bool] $Stale = $false) {
                $T['Results'].Add([pscustomobject]@{ Host = $env:COMPUTERNAME; StigId = 'R-1'; Severity = 'high'; Status = 'Open'; Title = 'r1'; Exception = $null })
                $T['ResultsContext'] = @{ Benchmark = 'Windows11'; ContentPath = '' }
                $T['ResultsStale'] = $Stale
                Set-WoscapGuiActionEnabled -Tag $T -Action Remediate -Enabled (-not $Stale)
            }
            # Mock bodies do not see common parameters such as -Confirm; read them from the mock's own frame.
            function script:Save-TestRemoveArgs {
                $frame = @(Get-PSCallStack | Where-Object { $_.InvocationInfo.MyCommand.Name -like 'PesterMock_*Remove-WoscapBenchmark*' })[0]
                $script:removeArgs = @{}
                foreach ($k in $frame.InvocationInfo.BoundParameters.Keys) {
                    if ($k -notin 'ErrorAction', 'WarningAction') { $script:removeArgs[$k] = $frame.InvocationInfo.BoundParameters[$k] }
                }
            }
            function script:Assert-TestIdle([hashtable] $T) {
                foreach ($k in 'ContentDownload','ContentUpdate','MenuContentDownload','MenuContentUpdate','Run','MenuRun') {
                    $T[$k].Enabled | Should -BeTrue -Because "$k must be restored after the content job"
                }
                $T['Busy'] | Should -BeNullOrEmpty
            }
        }
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-WoscapGuiContentDownload' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach {
        Set-ContentFlowMocks
        $script:Cache = New-TestCache (Join-Path $TestDrive ('cache-' + [guid]::NewGuid().ToString('N')))
        New-ContentFlowForm $script:Cache
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'does nothing when the Download dialog is cancelled' {
        InModuleScope woscap {
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            Should -Invoke Invoke-WoscapGuiScan -Times 0 -Exactly
            Should -Invoke Resolve-WoscapGuiDisaTerms -Times 0 -Exactly
            Should -Invoke Write-WoscapDisaTermsMarker -Times 0 -Exactly
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'does nothing when the DISA terms are declined' {
        InModuleScope woscap {
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Mock Resolve-WoscapGuiDisaTerms { @{ Proceed = $false; AcceptSwitch = $false; Remember = $true } }
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            Should -Invoke Invoke-WoscapGuiScan -Times 0 -Exactly
            Should -Invoke Write-WoscapDisaTermsMarker -Times 0 -Exactly
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'resolves the terms against the Cache folder root' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            Should -Invoke Resolve-WoscapGuiDisaTerms -Times 1 -Exactly -ParameterFilter { $CacheRoot -eq $Cache }
        }
    }

    It 'runs Save-WoscapStigContent with exactly the dialog options, Destination and AcceptDisaTerms when the gate says so' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = 'https://example.invalid/e.zip'; AllowScrape = $true; Force = $true } }
            Mock Resolve-WoscapGuiDisaTerms { @{ Proceed = $true; AcceptSwitch = $true; Remember = $false } }
            Mock Invoke-WoscapGuiScan { $script:runs.Add(@{ Command = $Command; Params = $ScanParameters.Clone() }) }
            $script:form.Tag['ContentDestination'].Text = "  $Cache  "
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            $script:runs.Count | Should -Be 1
            $script:runs[0].Command | Should -Be 'Save-WoscapStigContent'
            $p = $script:runs[0].Params
            @($p.Keys | Sort-Object) | Should -Be @('AcceptDisaTerms', 'AllowScrape', 'Benchmark', 'Destination', 'Force', 'Url')
            $p['Benchmark'] | Should -Be 'Edge'
            $p['Url'] | Should -Be 'https://example.invalid/e.zip'
            $p['AllowScrape'] | Should -BeTrue
            $p['Force'] | Should -BeTrue
            $p['AcceptDisaTerms'] | Should -BeTrue
            $p['Destination'] | Should -Be $Cache
        }
    }

    It 'passes only Benchmark when no option is set, the Cache folder is blank and the marker already exists' {
        InModuleScope woscap {
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Mock Invoke-WoscapGuiScan { $script:runs.Add(@{ Command = $Command; Params = $ScanParameters.Clone() }) }
            $script:form.Tag['ContentDestination'].Text = '   '
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            $script:runs.Count | Should -Be 1
            @($script:runs[0].Params.Keys) | Should -Be @('Benchmark')
        }
    }

    It 'disables every content action and Run/Remediate while the download runs' {
        InModuleScope woscap {
            Set-TestScanResults $script:form.Tag
            Update-WoscapGuiContentView -Tag $script:form.Tag
            $null = Select-TestRow $script:form.Tag 'Edge' 'V2R1'
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Mock Invoke-WoscapGuiScan { $script:busy = Get-TestBusyState $script:form.Tag }
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            foreach ($k in $script:busy.Keys) { $script:busy[$k] | Should -BeFalse -Because "$k must be disabled while the job runs" }
            # A grid click during the job must not re-enable Remove / Use for scan.
            Update-WoscapGuiContentSelection -Tag $script:form.Tag
            $script:form.Tag['ContentRemove'].Enabled | Should -BeFalse
            $script:form.Tag['ContentUseForScan'].Enabled | Should -BeFalse
        }
    }

    It 'on success refreshes the grid, selects the new revision, writes the marker when Remember was ticked and restores the UI' {
        $newXccdf = Add-TestRevision -Root $script:Cache -Bench 'Edge' -Rev 'V2R2' -Hash ('D' * 64) -Title 'Edge STIG'
        InModuleScope woscap -Parameters @{ Cache = $script:Cache; NewXccdf = $newXccdf } {
            param($Cache, $NewXccdf)
            $script:newXccdf = $NewXccdf
            Set-TestScanResults $script:form.Tag
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Mock Resolve-WoscapGuiDisaTerms { @{ Proceed = $true; AcceptSwitch = $true; Remember = $true } }
            Mock Invoke-WoscapGuiScan { & $OnSettled -Results @($script:newXccdf) -Outcome $script:none }
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            $t = $script:form.Tag
            $t['ContentGrid'].Rows.Count | Should -Be 4
            @($t['ContentGrid'].SelectedRows).Count | Should -Be 1
            $t['ContentGrid'].SelectedRows[0].Tag.Revision | Should -Be 'V2R2'
            $t['ContentGrid'].SelectedRows[0].Tag.Benchmark | Should -Be 'Edge'
            $t['ContentStatus'].Text | Should -Be "Downloaded Edge to $NewXccdf"
            Should -Invoke Write-WoscapDisaTermsMarker -Times 1 -Exactly -ParameterFilter { $CacheRoot -eq $Cache }
            Assert-TestIdle $t
            $t['Remediate'].Enabled | Should -BeTrue -Because 'a fresh scan result is remediable again'
            $t['ContentRemove'].Enabled | Should -BeTrue -Because 'the new revision is selected'
        }
    }

    It 'shows the new revision even when the filter named another benchmark' {
        $newXccdf = Add-TestRevision -Root $script:Cache -Bench 'Edge' -Rev 'V2R2' -Hash ('D' * 64) -Title 'Edge STIG'
        InModuleScope woscap -Parameters @{ NewXccdf = $newXccdf } {
            param($NewXccdf)
            $script:newXccdf = $NewXccdf
            Update-WoscapGuiContentView -Tag $script:form.Tag
            $script:form.Tag['ContentFilter'].SelectedItem = 'Windows11'
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Mock Invoke-WoscapGuiScan { & $OnSettled -Results @($script:newXccdf) -Outcome $script:none }
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            $script:form.Tag['ContentGrid'].SelectedRows[0].Tag.Revision | Should -Be 'V2R2'
        }
    }

    It 'does not write the marker on success when Remember was not ticked' {
        InModuleScope woscap {
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Mock Resolve-WoscapGuiDisaTerms { @{ Proceed = $true; AcceptSwitch = $true; Remember = $false } }
            Mock Invoke-WoscapGuiScan { & $OnSettled -Results @('C:\x\Edge\V2R1\U_Edge_Manual-xccdf.xml') -Outcome $script:none }
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            Should -Invoke Write-WoscapDisaTermsMarker -Times 0 -Exactly
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'never writes the marker on failure, shows the error and restores the UI respecting a stale scan' {
        InModuleScope woscap {
            Set-TestScanResults $script:form.Tag -Stale $true
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Mock Resolve-WoscapGuiDisaTerms { @{ Proceed = $true; AcceptSwitch = $true; Remember = $true } }
            Mock Invoke-WoscapGuiScan {
                & $OnError -Message 'boom'
                & $OnSettled -Results @() -Outcome $script:failed
            }
            $script:shown = @()
            Mock Show-WoscapGuiMessage { $script:shown += $Text }
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            Should -Invoke Write-WoscapDisaTermsMarker -Times 0 -Exactly
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Match 'boom'
            Assert-TestIdle $script:form.Tag
            $script:form.Tag['Remediate'].Enabled | Should -BeFalse -Because 'the scan results are stale'
        }
    }

    It 'treats a run that returned no path as a failure' {
        InModuleScope woscap {
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Mock Resolve-WoscapGuiDisaTerms { @{ Proceed = $true; AcceptSwitch = $true; Remember = $true } }
            Mock Invoke-WoscapGuiScan { & $OnSettled -Results @() -Outcome $script:none }
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            Should -Invoke Write-WoscapDisaTermsMarker -Times 0 -Exactly
            Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'restores the UI and writes no marker when the background job cannot start' {
        InModuleScope woscap {
            Set-TestScanResults $script:form.Tag
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Mock Resolve-WoscapGuiDisaTerms { @{ Proceed = $true; AcceptSwitch = $true; Remember = $true } }
            Mock Invoke-WoscapGuiScan { throw 'runspace exploded' }
            $script:shown = @()
            Mock Show-WoscapGuiMessage { $script:shown += $Text }
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            $script:shown[0] | Should -Match 'runspace exploded'
            Should -Invoke Write-WoscapDisaTermsMarker -Times 0 -Exactly
            Assert-TestIdle $script:form.Tag
            $script:form.Tag['Remediate'].Enabled | Should -BeTrue
        }
    }

    It 'refuses to start while a scan or remediation is running' {
        InModuleScope woscap {
            $script:form.Tag['Busy'] = 'Scan'
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiDownloadDialog -Times 0 -Exactly
            Should -Invoke Invoke-WoscapGuiScan -Times 0 -Exactly
            Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly
        }
    }
}

Describe 'Invoke-WoscapGuiContentUpdate' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach {
        Set-ContentFlowMocks
        $script:Cache = New-TestCache (Join-Path $TestDrive ('cache-' + [guid]::NewGuid().ToString('N')))
        New-ContentFlowForm $script:Cache
        InModuleScope woscap {
            $script:preview = @(
                [pscustomobject]@{ Benchmark = 'Edge'; Status = 'WhatIf'; FromRevision = 'V2R1'; ToRevision = ''; Reason = 'Would refresh from DISA' }
                [pscustomobject]@{ Benchmark = 'Windows11'; Status = 'WhatIf'; FromRevision = 'V1R6'; ToRevision = ''; Reason = 'Would refresh from DISA' }
            )
            $script:applied = @(
                [pscustomobject]@{ Benchmark = 'Edge'; Status = 'Updated'; FromRevision = 'V2R1'; ToRevision = 'V2R2'; Reason = '' }
                [pscustomobject]@{ Benchmark = 'Windows11'; Status = 'AlreadyCurrent'; FromRevision = 'V1R6'; ToRevision = 'V1R6'; Reason = '' }
            )
            # Records each run; answers the -WhatIf preview and the real run with the rows above.
            Mock Invoke-WoscapGuiScan {
                $script:runs.Add(@{ Command = $Command; Params = $ScanParameters.Clone() })
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results $script:preview -Outcome $script:none }
                else { & $OnSettled -Results $script:applied -Outcome $script:none }
            }
            Mock Show-WoscapGuiUpdateDialog { @{ Url = ''; AllowScrape = $false } }
            Mock Show-WoscapGuiUpdateConfirmDialog { $true }
        }
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'does nothing when the Update dialog is cancelled' {
        InModuleScope woscap {
            Mock Show-WoscapGuiUpdateDialog { $null }
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            Should -Invoke Invoke-WoscapGuiScan -Times 0 -Exactly
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'scopes to every cached benchmark when no row is selected' {
        InModuleScope woscap {
            Mock Show-WoscapGuiUpdateDialog { @{ Url = 'https://ignored.invalid/x.zip'; AllowScrape = $false } }
            Mock Show-WoscapGuiUpdateConfirmDialog { $false }
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiUpdateDialog -Times 1 -Exactly -ParameterFilter { $Benchmark -eq '' }
            $script:runs[0].Params.ContainsKey('Benchmark') | Should -BeFalse
            $script:runs[0].Params.ContainsKey('Url') | Should -BeFalse -Because '-Url is only valid with a single benchmark'
        }
    }

    It 'previews with -WhatIf only: never Confirm, never AcceptDisaTerms, terms not yet asked' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            Update-WoscapGuiContentView -Tag $script:form.Tag
            $null = Select-TestRow $script:form.Tag 'Edge' 'V2R1'
            Mock Show-WoscapGuiUpdateDialog { @{ Url = 'https://example.invalid/e.zip'; AllowScrape = $true } }
            Mock Show-WoscapGuiUpdateConfirmDialog { $false }
            Mock Resolve-WoscapGuiDisaTerms { @{ Proceed = $true; AcceptSwitch = $true; Remember = $false } }
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiUpdateDialog -Times 1 -Exactly -ParameterFilter { $Benchmark -eq 'Edge' }
            $script:runs.Count | Should -Be 1
            $script:runs[0].Command | Should -Be 'Update-WoscapBenchmark'
            $p = $script:runs[0].Params
            @($p.Keys | Sort-Object) | Should -Be @('AllowScrape', 'Benchmark', 'Destination', 'Url', 'WhatIf')
            $p['WhatIf'] | Should -BeTrue
            $p['Benchmark'] | Should -Be 'Edge'
            $p['Destination'] | Should -Be $Cache
            Should -Invoke Resolve-WoscapGuiDisaTerms -Times 0 -Exactly
        }
    }

    It 'confirms exactly the preview rows and never starts the real run when declined' {
        InModuleScope woscap {
            Mock Show-WoscapGuiUpdateConfirmDialog { $false }
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiUpdateConfirmDialog -Times 1 -Exactly -ParameterFilter {
                (@($Rows | ForEach-Object Benchmark) -join ',') -eq 'Edge,Windows11' }
            $script:runs.Count | Should -Be 1 -Because 'only the preview may run'
            Should -Invoke Resolve-WoscapGuiDisaTerms -Times 0 -Exactly
            Should -Invoke Show-WoscapGuiUpdateReport -Times 0 -Exactly
            Should -Invoke Write-WoscapDisaTermsMarker -Times 0 -Exactly
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'says Nothing to update and runs nothing more when the preview is empty' {
        InModuleScope woscap {
            $script:preview = @()
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            $script:runs.Count | Should -Be 1
            Should -Invoke Show-WoscapGuiUpdateConfirmDialog -Times 0 -Exactly
            $script:form.Tag['ContentStatus'].Text | Should -Match 'Nothing to update'
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'never starts the real run when the DISA terms are declined after confirming' {
        InModuleScope woscap {
            Mock Resolve-WoscapGuiDisaTerms { @{ Proceed = $false; AcceptSwitch = $false; Remember = $true } }
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            $script:runs.Count | Should -Be 1
            Should -Invoke Write-WoscapDisaTermsMarker -Times 0 -Exactly
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'runs for real with Confirm=$false and AcceptDisaTerms only after confirmation and terms, then reports and refreshes' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            Set-TestScanResults $script:form.Tag
            Mock Show-WoscapGuiUpdateDialog { @{ Url = ''; AllowScrape = $true } }
            Mock Resolve-WoscapGuiDisaTerms { @{ Proceed = $true; AcceptSwitch = $true; Remember = $true } }
            $script:busyAtReal = $null
            Mock Invoke-WoscapGuiScan {
                $script:runs.Add(@{ Command = $Command; Params = $ScanParameters.Clone() })
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results $script:preview -Outcome $script:none }
                else {
                    $script:busyAtReal = Get-TestBusyState $script:form.Tag
                    & $OnSettled -Results $script:applied -Outcome $script:none
                }
            }
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            $script:runs.Count | Should -Be 2
            $real = $script:runs[1].Params
            $script:runs[1].Command | Should -Be 'Update-WoscapBenchmark'
            @($real.Keys | Sort-Object) | Should -Be @('AcceptDisaTerms', 'AllowScrape', 'Confirm', 'Destination')
            $real['Confirm'] | Should -BeFalse
            $real['AcceptDisaTerms'] | Should -BeTrue
            $real['Destination'] | Should -Be $Cache
            Should -Invoke Show-WoscapGuiUpdateConfirmDialog -Times 1 -Exactly
            Should -Invoke Resolve-WoscapGuiDisaTerms -Times 1 -Exactly -ParameterFilter { $CacheRoot -eq $Cache }
            Should -Invoke Show-WoscapGuiUpdateReport -Times 1 -Exactly -ParameterFilter {
                (@($Result | ForEach-Object Status) -join ',') -eq 'Updated,AlreadyCurrent' }
            Should -Invoke Write-WoscapDisaTermsMarker -Times 1 -Exactly -ParameterFilter { $CacheRoot -eq $Cache }
            foreach ($k in $script:busyAtReal.Keys) { $script:busyAtReal[$k] | Should -BeFalse -Because "$k during the real run" }
            $script:form.Tag['ContentGrid'].Rows.Count | Should -Be 3 -Because 'the grid is refreshed afterwards'
            Assert-TestIdle $script:form.Tag
            $script:form.Tag['Remediate'].Enabled | Should -BeTrue
        }
    }

    It 'omits AcceptDisaTerms on the real run when the marker already exists' {
        InModuleScope woscap {
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            $script:runs.Count | Should -Be 2
            $script:runs[1].Params.ContainsKey('AcceptDisaTerms') | Should -BeFalse
            $script:runs[1].Params['Confirm'] | Should -BeFalse
            Should -Invoke Write-WoscapDisaTermsMarker -Times 0 -Exactly
        }
    }

    It 'never writes the marker when every benchmark failed to update' {
        InModuleScope woscap {
            Mock Resolve-WoscapGuiDisaTerms { @{ Proceed = $true; AcceptSwitch = $true; Remember = $true } }
            $script:applied = @([pscustomobject]@{ Benchmark = 'Edge'; Status = 'Failed'; FromRevision = 'V2R1'; ToRevision = ''; Reason = 'offline' })
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            Should -Invoke Write-WoscapDisaTermsMarker -Times 0 -Exactly
            Should -Invoke Show-WoscapGuiUpdateReport -Times 1 -Exactly
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'never writes the marker and restores the UI when the real run errors' {
        InModuleScope woscap {
            Mock Resolve-WoscapGuiDisaTerms { @{ Proceed = $true; AcceptSwitch = $true; Remember = $true } }
            Mock Invoke-WoscapGuiScan {
                $script:runs.Add(@{ Command = $Command; Params = $ScanParameters.Clone() })
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results $script:preview -Outcome $script:none }
                else { & $OnError -Message 'boom'; & $OnSettled -Results @() -Outcome $script:failed }
            }
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            Should -Invoke Write-WoscapDisaTermsMarker -Times 0 -Exactly
            Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly -ParameterFilter { $Text -match 'boom' }
            Should -Invoke Show-WoscapGuiUpdateReport -Times 0 -Exactly
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'restores the UI when the preview errors' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan { & $OnError -Message 'boom'; & $OnSettled -Results @() -Outcome $script:failed }
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiUpdateConfirmDialog -Times 0 -Exactly
            Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'restores the UI when the preview cannot start' {
        InModuleScope woscap {
            Mock Invoke-WoscapGuiScan { throw 'runspace exploded' }
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly -ParameterFilter { $Text -match 'runspace exploded' }
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'restores the UI and writes no marker when the real run cannot start' {
        InModuleScope woscap {
            Mock Resolve-WoscapGuiDisaTerms { @{ Proceed = $true; AcceptSwitch = $true; Remember = $true } }
            Mock Invoke-WoscapGuiScan {
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results $script:preview -Outcome $script:none }
                else { throw 'runspace exploded' }
            }
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly -ParameterFilter { $Text -match 'runspace exploded' }
            Should -Invoke Write-WoscapDisaTermsMarker -Times 0 -Exactly
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'refuses to start while a scan or remediation is running' {
        InModuleScope woscap {
            $script:form.Tag['Busy'] = 'Remediation'
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiUpdateDialog -Times 0 -Exactly
            Should -Invoke Invoke-WoscapGuiScan -Times 0 -Exactly
        }
    }
}

Describe 'Invoke-WoscapGuiContentRemove' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach {
        Set-ContentFlowMocks
        $script:Cache = New-TestCache (Join-Path $TestDrive ('cache-' + [guid]::NewGuid().ToString('N')))
        New-ContentFlowForm $script:Cache
        InModuleScope woscap { Update-WoscapGuiContentView -Tag $script:form.Tag }
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'does nothing without a selected row' {
        InModuleScope woscap {
            Invoke-WoscapGuiContentRemove -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiRemoveDialog -Times 0 -Exactly
            Should -Invoke Remove-WoscapBenchmark -Times 0 -Exactly
        }
    }

    It 'never removes when the dialog is cancelled' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            $null = Select-TestRow $script:form.Tag 'Windows11' 'V1R5'
            Invoke-WoscapGuiContentRemove -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiRemoveDialog -Times 1 -Exactly -ParameterFilter {
                $Benchmark -eq 'Windows11' -and $Revision -eq 'V1R5' -and $CacheRoot -eq $Cache }
            Should -Invoke Remove-WoscapBenchmark -Times 0 -Exactly
            $script:form.Tag['ContentGrid'].Rows.Count | Should -Be 3
        }
    }

    It 'removes exactly the selected revision with -Confirm:$false and the Cache folder' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            $null = Select-TestRow $script:form.Tag 'Windows11' 'V1R5'
            Mock Show-WoscapGuiRemoveDialog { @{ AllRevisions = $false } }
            Mock Remove-WoscapBenchmark { Save-TestRemoveArgs; 'removed' }
            Invoke-WoscapGuiContentRemove -Tag $script:form.Tag
            Should -Invoke Remove-WoscapBenchmark -Times 1 -Exactly
            @($script:removeArgs.Keys | Sort-Object) | Should -Be @('Benchmark', 'Confirm', 'Destination', 'Revision')
            $script:removeArgs['Benchmark'] | Should -Be 'Windows11'
            $script:removeArgs['Revision'] | Should -Be 'V1R5'
            $script:removeArgs['Destination'] | Should -Be $Cache
            [bool]$script:removeArgs['Confirm'] | Should -BeFalse
        }
    }

    It 'removes every revision of the benchmark without -Revision when chosen' {
        InModuleScope woscap {
            $null = Select-TestRow $script:form.Tag 'Windows11' 'V1R5'
            Mock Show-WoscapGuiRemoveDialog { @{ AllRevisions = $true } }
            Mock Remove-WoscapBenchmark { Save-TestRemoveArgs; 'removed' }
            Invoke-WoscapGuiContentRemove -Tag $script:form.Tag
            @($script:removeArgs.Keys | Sort-Object) | Should -Be @('Benchmark', 'Confirm', 'Destination')
            $script:removeArgs['Benchmark'] | Should -Be 'Windows11'
        }
    }

    It 'passes no Destination when the Cache folder is blank' {
        InModuleScope woscap {
            $null = Select-TestRow $script:form.Tag 'Edge' 'V2R1'
            $script:form.Tag['ContentDestination'].Text = '  '
            # As if the grid had been listed from the default root (the guard mock never lists it).
            $script:form.Tag['ContentListedRoot'] = Get-WoscapContentCacheRoot
            Mock Show-WoscapGuiRemoveDialog { @{ AllRevisions = $false } }
            Mock Remove-WoscapBenchmark { Save-TestRemoveArgs }
            Invoke-WoscapGuiContentRemove -Tag $script:form.Tag
            Should -Invoke Remove-WoscapBenchmark -Times 1 -Exactly
            $script:removeArgs.ContainsKey('Destination') | Should -BeFalse
            Should -Invoke Show-WoscapGuiRemoveDialog -Times 1 -Exactly -ParameterFilter { $CacheRoot -eq (Get-WoscapContentCacheRoot) }
        }
    }

    It 'shows a removal error and does not throw' {
        InModuleScope woscap {
            $null = Select-TestRow $script:form.Tag 'Edge' 'V2R1'
            Mock Show-WoscapGuiRemoveDialog { @{ AllRevisions = $false } }
            Mock Remove-WoscapBenchmark { throw 'access denied' }
            { Invoke-WoscapGuiContentRemove -Tag $script:form.Tag } | Should -Not -Throw
            Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly -ParameterFilter { $Text -match 'access denied' }
        }
    }

    It 'removes only the chosen revision from a real cache and leaves its sibling (real Remove-/Get-WoscapBenchmark)' {
        InModuleScope woscap -Parameters @{ Cache = $script:Cache } {
            param($Cache)
            Mock Remove-WoscapBenchmark {
                Save-TestRemoveArgs
                $splat = $script:removeArgs
                if (-not $splat['Destination']) { throw 'test tried to remove from the real content cache' }
                # Without -Confirm:$false the real cmdlet would block on a console prompt.
                if (-not $splat.ContainsKey('Confirm') -or $splat['Confirm']) { throw 'Remove-WoscapBenchmark would prompt' }
                & (Get-Item -LiteralPath function:Remove-WoscapBenchmark) @splat
            }
            $null = Select-TestRow $script:form.Tag 'Windows11' 'V1R5'
            Mock Show-WoscapGuiRemoveDialog { @{ AllRevisions = $false } }
            Invoke-WoscapGuiContentRemove -Tag $script:form.Tag
            Test-Path -LiteralPath (Join-Path $Cache 'Windows11\V1R5') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $Cache 'Windows11\V1R6') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $Cache 'Edge\V2R1') | Should -BeTrue
            $t = $script:form.Tag
            @($t['ContentGrid'].Rows | ForEach-Object { '{0}/{1}' -f $_.Tag.Benchmark, $_.Tag.Revision } | Sort-Object) |
                Should -Be @('Edge/V2R1', 'Windows11/V1R6')
            $t['ContentStatus'].Text | Should -Match 'Removed Windows11 V1R5'
            $t['ContentRemove'].Enabled | Should -BeFalse -Because 'the removed row is gone and nothing is selected'
        }
    }
}

Describe 'Invoke-WoscapGuiContentUseForScan' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach {
        Set-ContentFlowMocks
        $script:Cache = New-TestCache (Join-Path $TestDrive ('cache-' + [guid]::NewGuid().ToString('N')))
        $null = Add-TestRevision -Root $script:Cache -Bench 'Firewall' -Rev 'V1R1' -Hash ('E' * 64) -Title 'Firewall STIG'
        New-ContentFlowForm $script:Cache
        InModuleScope woscap {
            Update-WoscapGuiContentView -Tag $script:form.Tag
            $script:form.Tag['Tabs'].SelectedTab = $script:form.Tag['ContentTab']
        }
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'sets the exact Path, selects the matching pack, switches to the Scan tab and never scans' {
        InModuleScope woscap {
            $t = $script:form.Tag
            $t['Benchmark'].SelectedItem = 'Windows11'
            $row = Select-TestRow $t 'Edge' 'V2R1'
            Invoke-WoscapGuiContentUseForScan -Tag $t
            $t['Xccdf'].Text | Should -BeExactly ([string]$row.Tag.Path)
            $t['Benchmark'].SelectedItem | Should -Be 'Edge'
            $t['Tabs'].SelectedTab | Should -Be $t['ScanTab']
            $t['Status'].Text | Should -Not -Match 'Not_Reviewed'
            Should -Invoke Invoke-WoscapGuiRun -Times 0 -Exactly
            Should -Invoke Invoke-WoscapGuiScan -Times 0 -Exactly
        }
    }

    It 'warns about Not_Reviewed results and clears the pack selection when no pack matches' {
        InModuleScope woscap {
            $t = $script:form.Tag
            $t['Benchmark'].SelectedItem = 'Windows11'
            $row = Select-TestRow $t 'Firewall' 'V1R1'
            Invoke-WoscapGuiContentUseForScan -Tag $t
            $t['Xccdf'].Text | Should -BeExactly ([string]$row.Tag.Path)
            # A stale pack must not pair with this XCCDF; Run's validation then asks for one.
            $t['Benchmark'].SelectedIndex | Should -Be -1
            $t['Status'].Text | Should -Be "No content pack for 'Firewall'; results would be Not_Reviewed."
            $t['Tabs'].SelectedTab | Should -Be $t['ScanTab']
            Should -Invoke Invoke-WoscapGuiRun -Times 0 -Exactly
            Should -Invoke Invoke-WoscapGuiScan -Times 0 -Exactly
        }
    }

    It 'does nothing without a selected row' {
        InModuleScope woscap {
            $t = $script:form.Tag
            $t['Xccdf'].Text = 'C:\keep.xml'
            Invoke-WoscapGuiContentUseForScan -Tag $t
            $t['Xccdf'].Text | Should -Be 'C:\keep.xml'
            $t['Tabs'].SelectedTab | Should -Be $t['ContentTab']
        }
    }
}

Describe 'Shared busy state across scan, remediation and content jobs' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach {
        Set-ContentFlowMocks -RealRun
        $script:Cache = New-TestCache (Join-Path $TestDrive ('cache-' + [guid]::NewGuid().ToString('N')))
        $script:ScanXccdf = Join-Path $TestDrive 'scan-xccdf.xml'
        Set-Content -LiteralPath $script:ScanXccdf -Value '<Benchmark/>'
        New-ContentFlowForm $script:Cache
        InModuleScope woscap -Parameters @{ X = $script:ScanXccdf } {
            param($X)
            $t = $script:form.Tag
            $t['Xccdf'].Text = $X
            $t['Benchmark'].SelectedItem = 'Windows11'
            Update-WoscapGuiContentView -Tag $t
            Mock Get-WoscapGuiSelectedResult { @() }
            Mock Test-WoscapGuiElevated { $true }
        }
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'refuses every content action while a scan runs' {
        InModuleScope woscap -Parameters @{ X = $script:ScanXccdf } {
            param($X)
            $t = $script:form.Tag
            Mock Invoke-WoscapGuiScan { }
            Invoke-WoscapGuiRun -Tag $t | Should -BeTrue
            $t['Busy'] | Should -Be 'Scan'
            $null = Select-TestRow $t 'Edge' 'V2R1'
            Invoke-WoscapGuiContentDownload -Tag $t
            Invoke-WoscapGuiContentUpdate -Tag $t
            Invoke-WoscapGuiContentRemove -Tag $t
            Invoke-WoscapGuiContentUseForScan -Tag $t
            Should -Invoke Show-WoscapGuiDownloadDialog -Times 0 -Exactly
            Should -Invoke Show-WoscapGuiUpdateDialog -Times 0 -Exactly
            Should -Invoke Show-WoscapGuiRemoveDialog -Times 0 -Exactly
            Should -Invoke Remove-WoscapBenchmark -Times 0 -Exactly
            $t['Xccdf'].Text | Should -Be $X -Because 'Use for scan must not swap the XCCDF under a running scan'
            Should -Invoke Show-WoscapGuiMessage -Times 4 -Exactly
            $t['Run'].Enabled | Should -BeFalse
        }
    }

    It 'refuses every content action while a remediation runs' {
        InModuleScope woscap {
            $t = $script:form.Tag
            Set-TestScanResults $t
            Update-WoscapGuiView -Tag $t
            Mock Invoke-WoscapGuiScan { }
            Invoke-WoscapGuiRemediate -Tag $t
            $t['Busy'] | Should -Be 'Remediation'
            $null = Select-TestRow $t 'Edge' 'V2R1'
            Invoke-WoscapGuiContentDownload -Tag $t
            Invoke-WoscapGuiContentRemove -Tag $t
            Should -Invoke Show-WoscapGuiDownloadDialog -Times 0 -Exactly
            Should -Invoke Show-WoscapGuiRemoveDialog -Times 0 -Exactly
            Should -Invoke Show-WoscapGuiMessage -Times 2 -Exactly
        }
    }

    It 'marks a content job busy so Run and Remediate stay disabled' {
        InModuleScope woscap {
            $t = $script:form.Tag
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Mock Invoke-WoscapGuiScan { $script:busyKind = $script:form.Tag['Busy'] }
            Invoke-WoscapGuiContentDownload -Tag $t
            $script:busyKind | Should -Be 'Content'
            $t['Run'].Enabled | Should -BeFalse
        }
    }

    It 'a scan clears the busy state on <exit>' -ForEach @(
        @{ exit = 'success' }, @{ exit = 'error' }, @{ exit = 'start-throw' }
    ) {
        InModuleScope woscap -Parameters @{ Exit = $exit } {
            param($Exit)
            $script:exitKind = $Exit
            $t = $script:form.Tag
            Mock Invoke-WoscapGuiScan {
                switch ($script:exitKind) {
                    'success' { & $OnComplete -Results @() }
                    'error' { & $OnError -Message 'scan broke' }
                    'start-throw' { throw 'runspace exploded' }
                }
            }
            $null = Invoke-WoscapGuiRun -Tag $t
            $t['Busy'] | Should -BeNullOrEmpty
            Mock Show-WoscapGuiDownloadDialog { $null }
            Invoke-WoscapGuiContentDownload -Tag $t
            Should -Invoke Show-WoscapGuiDownloadDialog -Times 1 -Exactly
        }
    }

    It 'a remediation clears the busy state on <exit>' -ForEach @(
        @{ exit = 'cancel' }, @{ exit = 'nothing' }, @{ exit = 'preview-error' }, @{ exit = 'start-throw' },
        @{ exit = 'apply-success' }, @{ exit = 'apply-error' }
    ) {
        InModuleScope woscap -Parameters @{ Exit = $exit } {
            param($Exit)
            $script:exitKind = $Exit
            $t = $script:form.Tag
            Set-TestScanResults $t
            Update-WoscapGuiView -Tag $t
            $script:plan = @([pscustomobject]@{ StigId = 'R-1'; StigIds = @('R-1'); Title = 'r1'; Action = 'a1'; State = 'Planned'; Detail = '' })
            $script:inFlight = $null
            Mock Show-WoscapGuiRemediationDialog { if ($script:exitKind -ne 'cancel') { @('R-1') } }
            Mock Invoke-WoscapGuiScan {
                $script:inFlight = $script:form.Tag['Busy']
                if ($script:exitKind -eq 'start-throw') { throw 'runspace exploded' }
                if ($ScanParameters.ContainsKey('WhatIf')) {
                    if ($script:exitKind -eq 'preview-error') { & $OnError -Message 'broke'; return }
                    $plan = if ($script:exitKind -eq 'nothing') { @() } else { $script:plan }
                    & $OnSettled -Results $plan -Outcome $script:none
                } elseif ($script:exitKind -eq 'apply-error') {
                    & $OnError -Message 'broke'
                } else {
                    & $OnComplete -Results @([pscustomobject]@{ StigId = 'R-1'; StigIds = @('R-1'); Title = 'r1'; Action = 'a1'; State = 'Applied'; After = 'NotAFinding'; Detail = '' })
                }
            }
            Invoke-WoscapGuiRemediate -Tag $t
            $script:inFlight | Should -Be 'Remediation'
            $t['Busy'] | Should -BeNullOrEmpty
        }
    }
}

Describe 'Content actions target the listed cache root' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach {
        Set-ContentFlowMocks
        $script:Cache = New-TestCache (Join-Path $TestDrive ('cache-' + [guid]::NewGuid().ToString('N')))
        $script:Other = Join-Path $TestDrive ('other-' + [guid]::NewGuid().ToString('N'))
        New-ContentFlowForm $script:Cache
        InModuleScope woscap { Update-WoscapGuiContentView -Tag $script:form.Tag }
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'refuses <action> and asks for Refresh when the Cache folder was edited since the listing' -ForEach @(
        @{ action = 'Download' }, @{ action = 'Update' }, @{ action = 'Remove' }, @{ action = 'UseForScan' }
    ) {
        InModuleScope woscap -Parameters @{ Other = $script:Other; Action = $action } {
            param($Other, $Action)
            $t = $script:form.Tag
            $null = Select-TestRow $t 'Edge' 'V2R1'
            $t['Xccdf'].Text = 'C:\keep.xml'
            $t['ContentDestination'].Text = $Other
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Mock Show-WoscapGuiUpdateDialog { @{ Url = ''; AllowScrape = $false } }
            Mock Show-WoscapGuiRemoveDialog { @{ AllRevisions = $false } }
            & "Invoke-WoscapGuiContent$Action" -Tag $t
            Should -Invoke Invoke-WoscapGuiScan -Times 0 -Exactly
            Should -Invoke Remove-WoscapBenchmark -Times 0 -Exactly
            $t['Xccdf'].Text | Should -Be 'C:\keep.xml'
            Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly -ParameterFilter { $Text -match 'Refresh' }
        }
    }

    It 'proceeds once the edited Cache folder has been listed' {
        InModuleScope woscap -Parameters @{ Other = $script:Other } {
            param($Other)
            $t = $script:form.Tag
            $t['ContentDestination'].Text = $Other
            Update-WoscapGuiContentView -Tag $t
            Mock Show-WoscapGuiUpdateDialog { @{ Url = ''; AllowScrape = $false } }
            Mock Invoke-WoscapGuiScan { $script:runs.Add(@{ Command = $Command; Params = $ScanParameters.Clone() }) }
            Invoke-WoscapGuiContentUpdate -Tag $t
            $script:runs[0].Params['Destination'] | Should -Be $Other
        }
    }

    It 'refreshes and selects from the download root even if the Cache folder is edited during the job' {
        $newXccdf = Add-TestRevision -Root $script:Cache -Bench 'Edge' -Rev 'V2R2' -Hash ('D' * 64) -Title 'Edge STIG'
        InModuleScope woscap -Parameters @{ NewXccdf = $newXccdf; Other = $script:Other } {
            param($NewXccdf, $Other)
            $script:newXccdf = $NewXccdf; $script:other = $Other
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Mock Invoke-WoscapGuiScan {
                $script:form.Tag['ContentDestination'].Text = $script:other
                & $OnSettled -Results @($script:newXccdf) -Outcome $script:none
            }
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            $t = $script:form.Tag
            $t['ContentGrid'].Rows.Count | Should -Be 4
            $t['ContentGrid'].SelectedRows[0].Tag.Revision | Should -Be 'V2R2'
        }
    }

    It 'refreshes from the update root even if the Cache folder is edited during the job' {
        InModuleScope woscap -Parameters @{ Other = $script:Other } {
            param($Other)
            $script:other = $Other
            Mock Show-WoscapGuiUpdateDialog { @{ Url = ''; AllowScrape = $false } }
            Mock Show-WoscapGuiUpdateConfirmDialog { $true }
            Mock Invoke-WoscapGuiScan {
                $row = [pscustomobject]@{ Benchmark = 'Edge'; Status = 'WhatIf'; FromRevision = 'V2R1'; ToRevision = ''; Reason = '' }
                if ($ScanParameters.ContainsKey('WhatIf')) { & $OnSettled -Results @($row) -Outcome $script:none }
                else {
                    $script:form.Tag['ContentDestination'].Text = $script:other
                    & $OnSettled -Results @($row) -Outcome $script:none
                }
            }
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            $script:form.Tag['ContentGrid'].Rows.Count | Should -Be 3
        }
    }
}

Describe 'Follow-up failures after a successful content job' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach {
        Set-ContentFlowMocks
        $script:Cache = New-TestCache (Join-Path $TestDrive ('cache-' + [guid]::NewGuid().ToString('N')))
        New-ContentFlowForm $script:Cache
        InModuleScope woscap {
            $script:shown = @()
            Mock Show-WoscapGuiMessage { $script:shown += $Text }
            Mock Resolve-WoscapGuiDisaTerms { @{ Proceed = $true; AcceptSwitch = $true; Remember = $true } }
        }
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'reports a failing step after a successful download as completed, and still writes the marker' {
        InModuleScope woscap {
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Mock Select-WoscapGuiContentRow { throw 'select broke' }
            # The runner's tick catch turns a throwing OnSettled into OnError.
            Mock Invoke-WoscapGuiScan {
                try { & $OnSettled -Results @('C:\x\Edge\V2R2\U_Edge_Manual-xccdf.xml') -Outcome $script:none }
                catch { & $OnError -Message $_.Exception.Message }
            }
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Match 'completed, but a follow-up step failed: select broke'
            $script:shown[0] | Should -Not -Match 'Download failed'
            $script:form.Tag['ContentStatus'].Text | Should -Not -Match 'Download failed'
            Should -Invoke Write-WoscapDisaTermsMarker -Times 1 -Exactly
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'reports a failing report dialog after a successful update as completed, and still writes the marker' {
        InModuleScope woscap {
            Mock Show-WoscapGuiUpdateDialog { @{ Url = ''; AllowScrape = $false } }
            Mock Show-WoscapGuiUpdateConfirmDialog { $true }
            Mock Show-WoscapGuiUpdateReport { throw 'report broke' }
            Mock Invoke-WoscapGuiScan {
                if ($ScanParameters.ContainsKey('WhatIf')) {
                    & $OnSettled -Results @([pscustomobject]@{ Benchmark = 'Edge'; Status = 'WhatIf'; FromRevision = 'V2R1'; ToRevision = ''; Reason = '' }) -Outcome $script:none
                } else {
                    try { & $OnSettled -Results @([pscustomobject]@{ Benchmark = 'Edge'; Status = 'Updated'; FromRevision = 'V2R1'; ToRevision = 'V2R2'; Reason = '' }) -Outcome $script:none }
                    catch { & $OnError -Message $_.Exception.Message }
                }
            }
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            $script:shown.Count | Should -Be 1
            $script:shown[0] | Should -Match 'completed, but a follow-up step failed: report broke'
            $script:shown[0] | Should -Not -Match 'Update failed'
            $script:form.Tag['ContentStatus'].Text | Should -Not -Match 'Update failed'
            Should -Invoke Write-WoscapDisaTermsMarker -Times 1 -Exactly
            Assert-TestIdle $script:form.Tag
        }
    }
}

Describe 'DISA terms dialog failure' -Skip:(-not $script:IsSta) {
    BeforeAll {
        Mock -ModuleName woscap Get-WoscapGuiSettingsPath { Join-Path $TestDrive 'woscap\gui-settings.json' }   # never the real %LOCALAPPDATA%
    }
    BeforeEach {
        Set-ContentFlowMocks
        $script:Cache = New-TestCache (Join-Path $TestDrive ('cache-' + [guid]::NewGuid().ToString('N')))
        New-ContentFlowForm $script:Cache
        InModuleScope woscap {
            # The real gate against a marker-less TestDrive cache, with a dialog that throws.
            Mock Resolve-WoscapGuiDisaTerms { & (Get-Item -LiteralPath function:Resolve-WoscapGuiDisaTerms) -CacheRoot $CacheRoot }
            Mock Show-WoscapGuiDisaTermsDialog { throw 'dialog broke' }
        }
    }
    AfterEach { InModuleScope woscap { $script:form.Dispose() } }

    It 'shows the error and downloads nothing' {
        InModuleScope woscap {
            Mock Show-WoscapGuiDownloadDialog { @{ Benchmark = 'Edge'; Url = ''; AllowScrape = $false; Force = $false } }
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            Should -Invoke Invoke-WoscapGuiScan -Times 0 -Exactly
            Should -Invoke Write-WoscapDisaTermsMarker -Times 0 -Exactly
            Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly -ParameterFilter { $Text -match 'dialog broke' }
            Assert-TestIdle $script:form.Tag
        }
    }

    It 'shows the error and runs no real update' {
        InModuleScope woscap {
            Mock Show-WoscapGuiUpdateDialog { @{ Url = ''; AllowScrape = $false } }
            Mock Show-WoscapGuiUpdateConfirmDialog { $true }
            Mock Invoke-WoscapGuiScan {
                $script:runs.Add(@{ Command = $Command; Params = $ScanParameters.Clone() })
                & $OnSettled -Results @([pscustomobject]@{ Benchmark = 'Edge'; Status = 'WhatIf'; FromRevision = 'V2R1'; ToRevision = ''; Reason = '' }) -Outcome $script:none
            }
            Invoke-WoscapGuiContentUpdate -Tag $script:form.Tag
            $script:runs.Count | Should -Be 1 -Because 'only the preview may run'
            Should -Invoke Write-WoscapDisaTermsMarker -Times 0 -Exactly
            Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly -ParameterFilter { $Text -match 'dialog broke' }
            Assert-TestIdle $script:form.Tag
        }
    }
}

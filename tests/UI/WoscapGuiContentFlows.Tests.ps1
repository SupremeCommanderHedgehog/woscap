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
    function Set-ContentFlowMocks {
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
        Mock -ModuleName woscap Invoke-WoscapGuiRun { $false }
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
            function script:Assert-TestIdle([hashtable] $T) {
                foreach ($k in 'ContentDownload','ContentUpdate','MenuContentDownload','MenuContentUpdate','Run','MenuRun') {
                    $T[$k].Enabled | Should -BeTrue -Because "$k must be restored after the content job"
                }
                $T['ContentBusy'] | Should -BeFalse
            }
        }
    }
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-WoscapGuiContentDownload' -Skip:(-not $script:IsSta) {
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
            Set-WoscapGuiActionEnabled -Tag $script:form.Tag -Action Run -Enabled $false
            Invoke-WoscapGuiContentDownload -Tag $script:form.Tag
            Should -Invoke Show-WoscapGuiDownloadDialog -Times 0 -Exactly
            Should -Invoke Invoke-WoscapGuiScan -Times 0 -Exactly
            Should -Invoke Show-WoscapGuiMessage -Times 1 -Exactly
        }
    }
}

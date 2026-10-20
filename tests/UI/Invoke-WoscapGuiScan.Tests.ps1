BeforeDiscovery {
    # The scan is driven by a WinForms Timer whose Tick fires only under a running
    # message pump, and WinForms objects need an STA apartment. CI (Windows PowerShell
    # 5.1 console) is STA; guard so these tests SKIP (never fail) on an MTA host.
    $script:IsSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
}
BeforeAll {
    $script:Root = Split-Path $PSScriptRoot -Parent | Split-Path -Parent
    Import-Module (Join-Path $script:Root 'woscap.psd1') -Force
    Add-Type -AssemblyName System.Windows.Forms
    # A tiny real benchmark (one manual rule) keeps the background scan fast and needs
    # no elevation, while still emitting a per-rule Write-Progress record -- the record
    # that drives the timer tick through Format-WoscapGuiProgress.
    $script:Xccdf = Join-Path $script:Root 'tests/fixtures/single-rule-xccdf.xml'
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-WoscapGuiScan' -Skip:(-not $script:IsSta) {

    # Regression for the timer-tick closure detaching from module session state: the
    # tick called the module-PRIVATE Format-WoscapGuiProgress, which a .GetNewClosure()
    # scriptblock cannot resolve, so every progress record threw
    # 'Format-WoscapGuiProgress is not recognized...' -> the tick's catch fired OnError
    # -> a modal MessageBox re-entered the pump -> stacked errors / call-depth crash.
    It 'delivers progress + results from the real background scan with no tick error' {
        # $script: inside InModuleScope is the MODULE's scope, so pass the fixture path in.
        InModuleScope woscap -Parameters @{ Xccdf = $script:Xccdf } {
            param($Xccdf)
            $progress = [System.Collections.ArrayList]::new()
            $errors   = [System.Collections.ArrayList]::new()
            $done     = @{ Called = $false; Results = $null }

            $onProgress = { param($Percent, $Status, $Indeterminate)
                [void]$progress.Add(@{ Percent = $Percent; Status = $Status }) }.GetNewClosure()
            $onComplete = { param($Results)
                $done.Called = $true; $done.Results = @($Results) }.GetNewClosure()
            $onError    = { param($Message)
                [void]$errors.Add($Message) }.GetNewClosure()

            $splat = @{ XccdfPath = $Xccdf; Benchmark = 'Windows11' }
            Invoke-WoscapGuiScan -ScanParameters $splat `
                -OnProgress $onProgress -OnComplete $onComplete -OnError $onError

            # Pump the message loop until the scan completes (the Timer.Tick delivers
            # results on this thread) or a generous timeout elapses.
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            while (-not $done.Called -and $sw.Elapsed.TotalSeconds -lt 30) {
                [System.Windows.Forms.Application]::DoEvents()
                Start-Sleep -Milliseconds 25
            }

            $errors        | Should -BeNullOrEmpty -Because 'the tick must resolve Format-WoscapGuiProgress'
            $done.Called   | Should -BeTrue -Because 'OnComplete must fire once the scan finishes'
            @($done.Results).Count | Should -Be 1
            $progress.Count | Should -BeGreaterThan 0 -Because 'the per-rule Write-Progress must reach OnProgress'
        }
    }

    It 'rejects a command outside the allowlist' {
        InModuleScope woscap {
            { Invoke-WoscapGuiScan -Command 'Get-Process' -ScanParameters @{} } | Should -Throw
        }
    }

    It 'runs Invoke-WoscapRemediation in the background when asked' {
        # Empty input + -WhatIf: the cmdlet plans nothing and can write nothing.
        InModuleScope woscap {
            $done   = @{ Called = $false; Count = -1 }
            $errors = [System.Collections.ArrayList]::new()
            $onComplete = { param($Results) $done.Called = $true; $done.Count = @($Results).Count }.GetNewClosure()
            $onError    = { param($Message) [void]$errors.Add($Message) }.GetNewClosure()
            Invoke-WoscapGuiScan -Command 'Invoke-WoscapRemediation' `
                -ScanParameters @{ Result = @(); WhatIf = $true; Quiet = $true } `
                -OnComplete $onComplete -OnError $onError
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            while (-not $done.Called -and $sw.Elapsed.TotalSeconds -lt 30) {
                [System.Windows.Forms.Application]::DoEvents()
                Start-Sleep -Milliseconds 25
            }
            $errors      | Should -BeNullOrEmpty
            $done.Called | Should -BeTrue
            $done.Count  | Should -Be 0
        }
    }

    It 'fires OnSettled once, last, with the results and the classified outcome (<Case>)' -ForEach @(
        @{ Case = 'clean';       Params = @{ Result = @(); WhatIf = $true; Quiet = $true };                                       Order = 'Complete,Settled'; Kind = 'None' }
        @{ Case = 'terminating'; Params = @{ Result = @(); WhatIf = $true; Quiet = $true; ContentPath = 'Z:\woscap-no-such-pack' }; Order = 'Error,Settled';    Kind = 'Error' }
    ) {
        # -WhatIf, empty input: nothing can be written; a missing pack throws before any planning.
        InModuleScope woscap -Parameters @{ Params = $Params; Order = $Order; Kind = $Kind } {
            param($Params, $Order, $Kind)
            $calls = [System.Collections.ArrayList]::new()
            $settled = @{ Outcome = $null; Results = $null }
            $onComplete = { param($Results) [void]$calls.Add('Complete') }.GetNewClosure()
            $onError    = { param($Message) [void]$calls.Add('Error') }.GetNewClosure()
            $onSettled  = { param($Results, $Outcome)
                [void]$calls.Add('Settled'); $settled.Outcome = $Outcome; $settled.Results = @($Results) }.GetNewClosure()
            Invoke-WoscapGuiScan -Command 'Invoke-WoscapRemediation' -ScanParameters $Params `
                -OnComplete $onComplete -OnError $onError -OnSettled $onSettled
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            while ($calls -notcontains 'Settled' -and $sw.Elapsed.TotalSeconds -lt 30) {
                [System.Windows.Forms.Application]::DoEvents()
                Start-Sleep -Milliseconds 25
            }
            # Let any stray late callback land before asserting "once".
            1..5 | ForEach-Object { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 30 }
            ($calls -join ',') | Should -Be $Order
            $settled.Outcome.Kind | Should -Be $Kind
            @($settled.Results).Count | Should -Be 0
        }
    }
}

function Invoke-WoscapGuiScan {
    <#
        Runs Invoke-WoscapScan in a background runspace so the WinForms UI stays
        responsive. A WinForms Timer polls the runspace's Progress stream and
        completion state, firing the supplied callbacks ON THE UI THREAD (the Timer
        ticks there). Non-blocking: returns immediately after starting the timer.

        Callbacks:
          OnProgress  & $OnProgress -Percent <int> -Status <string> -Indeterminate <bool>
          OnComplete  & $OnComplete -Results <object[]>
          OnWarning   & $OnWarning -Message <string> -Count <int>
          OnError     & $OnError -Message <string>

        Completion is classified by Resolve-WoscapGuiCompletion: OnComplete always fires
        first (results are always delivered). Then, if the scan ALSO reported errors, the
        outcome is a WARNING when results came back (e.g. one host down among several) or
        an ERROR when nothing came back or the scan terminated -- so a partial success is
        never presented as a total failure, and accumulated error detail is not lost.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $ScanParameters,
        [scriptblock] $OnProgress,
        [scriptblock] $OnComplete,
        [scriptblock] $OnWarning,
        [scriptblock] $OnError,
        [int] $PollIntervalMs = 150
    )
    $manifest = Join-Path $script:WoscapModuleRoot 'woscap.psd1'

    $ps = [powershell]::Create()
    try {
        # Fresh runspace: no -Force needed (nothing is loaded yet). No -Quiet either --
        # the Write-Host summary lands harmlessly in this runspace's Information stream,
        # while the engine's Write-Progress must reach $ps.Streams.Progress for the bar.
        [void]$ps.AddScript('param($mf, $sp) Import-Module $mf; Invoke-WoscapScan @sp')
        [void]$ps.AddArgument($manifest)
        [void]$ps.AddArgument($ScanParameters)
        $async = $ps.BeginInvoke()
    } catch {
        $ps.Dispose()
        throw
    }

    # Mutable state shared across timer ticks (closures capture by value, so mutate
    # the CONTENTS of a hashtable).
    $state = @{ ProgressIndex = 0 }

    # .GetNewClosure() (below) rebinds the tick to a fresh dynamic module, DETACHING it
    # from woscap's session state -- so the module-private Format-WoscapGuiProgress would
    # NOT resolve by bare name inside it (it would throw 'not recognized' every tick).
    # Capture the function's module-bound scriptblock now, while we ARE in module scope,
    # and invoke it with '&' so it still runs in woscap's session state.
    $formatProgress    = ${function:Format-WoscapGuiProgress}
    $resolveCompletion = ${function:Resolve-WoscapGuiCompletion}

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = $PollIntervalMs

    $tick = {
        try {
            # Drain any new progress records via the captured formatter (see above).
            while ($state.ProgressIndex -lt $ps.Streams.Progress.Count) {
                $rec = $ps.Streams.Progress[$state.ProgressIndex]
                $state.ProgressIndex++
                if ($OnProgress) {
                    # $null => a record the formatter drops (e.g. the final -Completed frame).
                    $f = & $formatProgress -Record $rec
                    if ($f) { & $OnProgress -Percent $f.Percent -Status $f.Text -Indeterminate $f.Indeterminate }
                }
            }

            if ($async.IsCompleted) {
                $timer.Stop()
                try {
                    $results = @($ps.EndInvoke($async))
                    # Deliver results first so the grid populates, THEN classify the outcome:
                    # clean (None), partial success (Warning), or failure (Error).
                    if ($OnComplete) { & $OnComplete -Results $results }
                    $outcome = & $resolveCompletion -Results $results `
                        -ErrorRecords @($ps.Streams.Error) -WarningRecords @($ps.Streams.Warning)
                    switch ($outcome.Kind) {
                        'Warning' { if ($OnWarning) { & $OnWarning -Message $outcome.Message -Count $outcome.Count } }
                        'Error'   { if ($OnError)   { & $OnError -Message $outcome.Message } }
                    }
                } catch {
                    # Terminating error: join any accumulated per-host/per-rule detail so the
                    # root cause is not lost behind the final exception message.
                    $outcome = & $resolveCompletion -Results @() `
                        -ErrorRecords @($ps.Streams.Error) -WarningRecords @($ps.Streams.Warning) `
                        -TerminatingError $_.Exception.Message
                    if ($OnError) { & $OnError -Message $outcome.Message }
                } finally {
                    $ps.Dispose()
                    $timer.Dispose()
                }
            }
        } catch {
            # Contain unexpected tick errors (e.g. a throwing OnProgress) so they do not
            # bubble onto the UI message pump and crash the app.
            if ($OnError) { & $OnError -Message $_.Exception.Message }
        }
    }.GetNewClosure()

    try {
        $timer.Add_Tick($tick)
        $timer.Start()
    } catch {
        $timer.Dispose()
        if (-not $async.IsCompleted) { $ps.Stop() }
        $ps.Dispose()
        throw
    }
}

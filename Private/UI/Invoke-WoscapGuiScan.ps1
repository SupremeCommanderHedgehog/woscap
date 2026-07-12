function Invoke-WoscapGuiScan {
    <#
        Runs Invoke-WoscapScan in a background runspace so the WinForms UI stays
        responsive. A WinForms Timer polls the runspace's Progress stream and
        completion state, firing the supplied callbacks ON THE UI THREAD (the Timer
        ticks there). Non-blocking: returns immediately after starting the timer.

        Callbacks:
          OnProgress  & $OnProgress -Percent <int> -Status <string> -Indeterminate <bool>
          OnComplete  & $OnComplete -Results <object[]>
          OnError     & $OnError -Message <string>

        Note: OnComplete fires first (results always delivered), THEN OnError fires if the
        scan reported errors -- so the final UI state reflects the failure, not a false
        'done', while any partial results are still shown.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $ScanParameters,
        [scriptblock] $OnProgress,
        [scriptblock] $OnComplete,
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
    $formatProgress = ${function:Format-WoscapGuiProgress}

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = $PollIntervalMs

    $tick = {
        try {
            # Drain any new progress records via the captured formatter (see above).
            while ($state.ProgressIndex -lt $ps.Streams.Progress.Count) {
                $rec = $ps.Streams.Progress[$state.ProgressIndex]
                $state.ProgressIndex++
                if ($OnProgress) {
                    $f = & $formatProgress -Record $rec
                    & $OnProgress -Percent $f.Percent -Status $f.Text -Indeterminate $f.Indeterminate
                }
            }

            if ($async.IsCompleted) {
                $timer.Stop()
                try {
                    $results = @($ps.EndInvoke($async))
                    # Deliver results first so the grid populates, THEN surface any error so
                    # the final status reflects the failure instead of a false 'Done.'.
                    if ($OnComplete) { & $OnComplete -Results $results }
                    if ($ps.HadErrors -and $ps.Streams.Error.Count -gt 0 -and $OnError) {
                        $errText = ($ps.Streams.Error | ForEach-Object { $_.ToString() }) -join "`n"
                        & $OnError -Message $errText
                    }
                } catch {
                    if ($OnError) { & $OnError -Message $_.Exception.Message }
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

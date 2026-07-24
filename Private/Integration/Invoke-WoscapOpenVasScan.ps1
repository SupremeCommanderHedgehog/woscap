function Invoke-WoscapOpenVasScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Server,
        [int] $Port = 9390,
        [Parameter(Mandatory)] [pscredential] $Credential,
        [Parameter(Mandatory)] [string[]] $Targets,
        [Parameter(Mandatory)] [string] $ScanConfigId,
        [Parameter(Mandatory)] [string] $ScannerId,
        # gvmd's create_target requires a port spec: a port_list id OR an explicit
        # port_range. PortListId (a gvmd port-list UUID) wins when set; otherwise
        # PortRange is sent. Default scans all TCP ports (thorough; override for speed).
        [string] $PortListId,
        [string] $PortRange = 'T:1-65535',
        # Optional credentials for an authenticated scan (deep local checks — e.g. a real
        # Windows/SMB compliance scan). Without them gvmd runs an unauthenticated scan.
        [string] $SmbCredentialId,
        [string] $SshCredentialId,
        [int] $SshCredentialPort = 22,
        # gvmd alive test, e.g. 'Consider Alive' for hosts that drop pings (firewalled Windows).
        [string] $AliveTest,
        [int] $PollSeconds = 15,
        [int] $TimeoutMinutes = 60,
        [switch] $SkipCertificateCheck,
        [int] $RequestTimeoutMs = 30000,
        [int] $ReportTimeoutMs = 300000
    )

    $conn = Connect-WoscapGmpStream -Server $Server -Port $Port -TimeoutMs $RequestTimeoutMs -SkipCertificateCheck:$SkipCertificateCheck
    if (-not $conn) { return $null }   # Connect already warned

    # Shared mutable flags: a hashtable is one object, so a nested scriptblock can set
    # .Failed / .Dirty and the caller sees it (a plain $var assignment would stay scope-local).
    # Dirty means a request threw mid-exchange, so the socket may hold an unread partial reply
    # and can no longer be trusted for a clean request/response (used to gate teardown below).
    $state = @{ Failed = $false; Dirty = $false }
    # Single source of truth for "is this GMP response a 2xx success" — used by both the
    # request path and the teardown path so they can't drift.
    $is2xx = {
        param($resp)
        if (-not ($resp -and $resp.DocumentElement)) { return $false }
        $st = 0
        if (-not [int]::TryParse($resp.DocumentElement.GetAttribute('status'), [ref]$st)) { return $false }
        ($st -ge 200 -and $st -lt 300)
    }
    $send = {
        param([string] $Step, [string] $Request, [int] $Timeout = 0)
        $useTimeout = if ($Timeout -gt 0) { $Timeout } else { $RequestTimeoutMs }
        try {
            $resp = Send-WoscapGmpRequest -Stream $conn.Stream -Request $Request -TimeoutMs $useTimeout
        } catch {
            Write-Warning "woscap: OpenVAS GMP $Step failed: $_"
            $state.Failed = $true; $state.Dirty = $true   # partial reply may be left unread on the socket
            return $null
        }
        if (& $is2xx $resp) { return $resp }
        # Not a success: give a specific message for a missing/non-numeric status vs a real error code.
        $raw = $resp.DocumentElement.GetAttribute('status')
        $st = 0
        if (-not [int]::TryParse($raw, [ref]$st)) {
            Write-Warning "woscap: OpenVAS GMP $Step returned a response with no valid status attribute."
        } else {
            Write-Warning "woscap: OpenVAS GMP $Step returned status $st ($($resp.DocumentElement.GetAttribute('status_text')))."
        }
        $state.Failed = $true; return $null
    }

    # Declared before the try so the finally can tear down whatever was created.
    $targetId = $null
    $taskId   = $null
    $effectivePoll = [System.Math]::Max(1, $PollSeconds)   # never a 0s busy-loop

    try {
        $esc  = { param($s) [System.Security.SecurityElement]::Escape([string]$s) }
        $user = & $esc $Credential.UserName
        $pass = & $esc $Credential.GetNetworkCredential().Password
        $null = & $send 'authenticate' "<authenticate><credentials><username>$user</username><password>$pass</password></credentials></authenticate>"
        if ($state.Failed) { return $null }

        $hosts = & $esc ($Targets -join ', ')
        $name  = 'woscap-' + ([System.Guid]::NewGuid().ToString('N'))
        # gvmd rejects create_target with 400 unless a port_list or port_range is given.
        if ($PortListId) {
            $portXml = "<port_list id='$(& $esc $PortListId)'/>"
        } else {
            $portXml = "<port_range>$(& $esc $PortRange)</port_range>"
        }
        # Optional authenticated-scan credentials + alive test.
        $credXml = ''
        if ($SmbCredentialId) { $credXml += "<smb_credential id='$(& $esc $SmbCredentialId)'/>" }
        if ($SshCredentialId) { $credXml += "<ssh_credential id='$(& $esc $SshCredentialId)'><port>$([int]$SshCredentialPort)</port></ssh_credential>" }
        $aliveXml = if ($AliveTest) { "<alive_tests>$(& $esc $AliveTest)</alive_tests>" } else { '' }
        $tResp = & $send 'create_target' "<create_target><name>$name</name><hosts>$hosts</hosts>$portXml$credXml$aliveXml</create_target>"
        if ($state.Failed) { return $null }
        $targetId = $tResp.DocumentElement.GetAttribute('id')
        if (-not $targetId) { Write-Warning "woscap: OpenVAS GMP create_target returned no target id."; return $null }

        $cfg = & $esc $ScanConfigId
        $scn = & $esc $ScannerId
        $kResp = & $send 'create_task' "<create_task><name>$name</name><config id='$cfg'/><target id='$targetId'/><scanner id='$scn'/></create_task>"
        if ($state.Failed) { return $null }
        $taskId = $kResp.DocumentElement.GetAttribute('id')
        if (-not $taskId) { Write-Warning "woscap: OpenVAS GMP create_task returned no task id."; return $null }

        $sResp = & $send 'start_task' "<start_task task_id='$taskId'/>"
        if ($state.Failed) { return $null }
        $ridNode  = $sResp.DocumentElement.SelectSingleNode('report_id')
        $reportId = if ($ridNode) { $ridNode.InnerText } else { $null }
        if (-not $reportId) { Write-Warning "woscap: OpenVAS GMP start_task returned no report id."; return $null }

        # Poll get_tasks until the task reaches a terminal state, or give up at the timeout.
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        while ($true) {
            $gResp = & $send 'get_tasks' "<get_tasks task_id='$taskId'/>"
            if ($state.Failed) { return $null }
            $statusNode = $gResp.DocumentElement.SelectSingleNode('task/status')
            $taskStatus = if ($statusNode) { $statusNode.InnerText } else { '' }
            if ($taskStatus -eq 'Done') { break }
            if (@('Stopped', 'Interrupted', 'Stop Requested', 'Internal Error') -contains $taskStatus) {
                Write-Warning "woscap: OpenVAS scan on '$Server' ended in terminal state '$taskStatus' without completing."
                return $null
            }
            if ($sw.Elapsed.TotalMinutes -ge $TimeoutMinutes) {
                $progNode = $gResp.DocumentElement.SelectSingleNode('task/progress')
                $prog = if ($progNode) { $progNode.InnerText } else { '?' }
                Write-Warning "woscap: OpenVAS scan on '$Server' timed out after $TimeoutMinutes min (status '$taskStatus', progress $prog%)."
                return $null
            }
            Start-Sleep -Seconds $effectivePoll
        }

        # details='1' returns the individual <result> elements (gvmd defaults to details=0 =
        # metadata only); ignore_pagination='1' returns the full result set, not just page 1.
        # A real report is large, so use the longer report timeout.
        $rResp = & $send 'get_reports' "<get_reports report_id='$reportId' details='1' ignore_pagination='1'/>" $ReportTimeoutMs
        if ($state.Failed) { return $null }
        return $rResp.OuterXml
    } finally {
        # Best-effort teardown of the target+task this run created, so repeated scans don't
        # accumulate orphaned woscap-* objects on gvmd. Deletes need the still-open stream,
        # so run them before disposing it. A TIMED-OUT scan leaves the task 'Running', and
        # gvmd rejects delete_task on an active task — so stop it first (a no-op if already
        # finished), then delete. If a delete still doesn't succeed the object is surfaced
        # via a warning rather than left silently behind. Task first (it references target).
        if ($conn.Stream) {
            # Only drive request/response teardown on a stream that's still in sync. If a
            # request threw mid-exchange ($state.Dirty), the socket may hold an unread partial
            # reply, so a stop/delete "response" would actually be misaligned leftover bytes —
            # surface the leak instead of reading garbage.
            if (-not $state.Dirty) {
                $sendQuiet = {
                    param([string] $Request)
                    try { Send-WoscapGmpRequest -Stream $conn.Stream -Request $Request -TimeoutMs $RequestTimeoutMs } catch { $null }
                }
                $warnIfLeft = {
                    param([string] $Step, $resp)
                    if (-not (& $is2xx $resp)) { Write-Warning "woscap: OpenVAS GMP $Step did not succeed; a woscap-* object may remain on '$Server'." }
                }
                if ($taskId) {
                    $null = & $sendQuiet "<stop_task task_id='$taskId'/>"   # no-op if the task already finished
                    & $warnIfLeft 'delete_task' (& $sendQuiet "<delete_task task_id='$taskId' ultimate='1'/>")
                }
                if ($targetId) {
                    & $warnIfLeft 'delete_target' (& $sendQuiet "<delete_target target_id='$targetId'/>")
                }
            } elseif ($taskId -or $targetId) {
                Write-Warning "woscap: OpenVAS GMP connection to '$Server' was lost mid-request; a woscap-* target/task may remain (clean up manually)."
            }
            $conn.Stream.Dispose()
        }
        if ($conn.Client) { $conn.Client.Close() }
    }
}

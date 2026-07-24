BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) 'woscap.psd1') -Force
    $script:Cred = [pscredential]::new('admin', (ConvertTo-SecureString 'pw' -AsPlainText -Force))
}
AfterAll { Remove-Module woscap -Force -ErrorAction SilentlyContinue }

Describe 'Invoke-WoscapOpenVasScan' {
    It 'drives create->start->poll->fetch, requests full report details, and cleans up server-side objects' {
        InModuleScope woscap -Parameters @{ Cred = $script:Cred } {
            Mock Connect-WoscapGmpStream { [pscustomobject]@{ Client = $null; Stream = [System.IO.MemoryStream]::new() } }
            Mock Start-Sleep {}
            $script:calls = @()
            $script:polls = 0
            Mock Send-WoscapGmpRequest {
                $script:calls += $Request
                if ($Request -like '*<authenticate>*') { return [xml]'<authenticate_response status="200" status_text="OK"/>' }
                if ($Request -like '*<create_target>*') { return [xml]'<create_target_response status="201" id="tgt-1"/>' }
                if ($Request -like '*<create_task>*')   { return [xml]'<create_task_response status="201" id="task-1"/>' }
                if ($Request -like '*<start_task*')      { return [xml]'<start_task_response status="202"><report_id>rep-1</report_id></start_task_response>' }
                if ($Request -like '*<get_tasks*') {
                    $script:polls = ($script:polls + 1)
                    if ($script:polls -ge 2) { return [xml]'<get_tasks_response status="200"><task id="task-1"><status>Done</status><progress>100</progress></task></get_tasks_response>' }
                    return [xml]'<get_tasks_response status="200"><task id="task-1"><status>Running</status><progress>40</progress></task></get_tasks_response>'
                }
                if ($Request -like '*<get_reports*') { return [xml]'<get_reports_response status="200"><report id="rep-1"><results><result><name>x</name></result></results></report></get_reports_response>' }
                if ($Request -like '*<delete_task*')   { return [xml]'<delete_task_response status="200"/>' }
                if ($Request -like '*<delete_target*') { return [xml]'<delete_target_response status="200"/>' }
                throw "unexpected request: $Request"
            }

            $report = Invoke-WoscapOpenVasScan -Server 'gvm' -Credential $Cred `
                -Targets @('10.0.0.5') -ScanConfigId 'cfg-1' -ScannerId 'scn-1' -PollSeconds 0

            $report | Should -Match '<result>'
            $report | Should -Match 'rep-1'
            # gvmd rejects create_target without a port spec; default is a port_range.
            ($script:calls | Where-Object { $_ -like '*<create_target>*' }) | Should -Match '<port_range>T:1-65535</port_range>'
            ($script:calls | Where-Object { $_ -like '*<create_task>*' }) | Should -Match "target id='tgt-1'"
            ($script:calls | Where-Object { $_ -like '*<start_task*' })    | Should -Match "task_id='task-1'"
            ($script:calls | Where-Object { $_ -like '*<get_reports*' })   | Should -Match "details='1'"
            ($script:calls | Where-Object { $_ -like '*<get_reports*' })   | Should -Match "ignore_pagination='1'"
            ($script:calls | Where-Object { $_ -like '*<delete_task*' })   | Should -Match "task_id='task-1'"
            ($script:calls | Where-Object { $_ -like '*<delete_target*' }) | Should -Match "target_id='tgt-1'"
            # authenticate, create_target, create_task, start_task, get_tasks x2, get_reports, delete_task, delete_target
            Should -Invoke Send-WoscapGmpRequest -Times 9 -Exactly
            # PollSeconds 0 must be clamped to a real sleep, not a busy-loop
            Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -ge 1 }
        }
    }
    It 'uses a port_list id in create_target when PortListId is supplied (no port_range)' {
        InModuleScope woscap -Parameters @{ Cred = $script:Cred } {
            Mock Connect-WoscapGmpStream { [pscustomobject]@{ Client = $null; Stream = [System.IO.MemoryStream]::new() } }
            Mock Start-Sleep {}
            $script:ctCall = $null
            Mock Send-WoscapGmpRequest {
                if ($Request -like '*<create_target>*') { $script:ctCall = $Request; return [xml]'<create_target_response status="201" id="t"/>' }
                if ($Request -like '*<authenticate>*')  { return [xml]'<authenticate_response status="200"/>' }
                if ($Request -like '*<create_task>*')   { return [xml]'<create_task_response status="201" id="k"/>' }
                if ($Request -like '*<start_task*')      { return [xml]'<start_task_response status="202"><report_id>r</report_id></start_task_response>' }
                if ($Request -like '*<get_tasks*')       { return [xml]'<get_tasks_response status="200"><task id="k"><status>Done</status></task></get_tasks_response>' }
                if ($Request -like '*<get_reports*')     { return [xml]'<get_reports_response status="200"><report><results><result><name>x</name></result></results></report></get_reports_response>' }
                return [xml]'<ok status="200"/>'
            }
            $null = Invoke-WoscapOpenVasScan -Server 'gvm' -Credential $Cred -Targets @('h') `
                -ScanConfigId 'c' -ScannerId 's' -PortListId 'pl-uuid-9' -PollSeconds 0
            $script:ctCall | Should -Match "<port_list id='pl-uuid-9'/>"
            $script:ctCall | Should -Not -Match '<port_range>'
        }
    }
    It 'attaches SMB/SSH credentials and an alive test to create_target when supplied' {
        InModuleScope woscap -Parameters @{ Cred = $script:Cred } {
            Mock Connect-WoscapGmpStream { [pscustomobject]@{ Client = $null; Stream = [System.IO.MemoryStream]::new() } }
            Mock Start-Sleep {}
            $script:ctCall = $null
            Mock Send-WoscapGmpRequest {
                if ($Request -like '*<create_target>*') { $script:ctCall = $Request; return [xml]'<create_target_response status="201" id="t"/>' }
                if ($Request -like '*<authenticate>*')  { return [xml]'<authenticate_response status="200"/>' }
                if ($Request -like '*<create_task>*')   { return [xml]'<create_task_response status="201" id="k"/>' }
                if ($Request -like '*<start_task*')      { return [xml]'<start_task_response status="202"><report_id>r</report_id></start_task_response>' }
                if ($Request -like '*<get_tasks*')       { return [xml]'<get_tasks_response status="200"><task id="k"><status>Done</status></task></get_tasks_response>' }
                if ($Request -like '*<get_reports*')     { return [xml]'<get_reports_response status="200"><report><results><result><name>x</name></result></results></report></get_reports_response>' }
                return [xml]'<ok status="200"/>'
            }
            $null = Invoke-WoscapOpenVasScan -Server 'gvm' -Credential $Cred -Targets @('h') `
                -ScanConfigId 'c' -ScannerId 's' -PortListId 'pl' `
                -SmbCredentialId 'smb-9' -SshCredentialId 'ssh-9' -SshCredentialPort 2222 `
                -AliveTest 'Consider Alive' -PollSeconds 0
            $script:ctCall | Should -Match "<smb_credential id='smb-9'/>"
            $script:ctCall | Should -Match "<ssh_credential id='ssh-9'><port>2222</port></ssh_credential>"
            $script:ctCall | Should -Match '<alive_tests>Consider Alive</alive_tests>'
        }
    }
    It 'warns and returns $null when authentication is rejected' {
        InModuleScope woscap -Parameters @{ Cred = $script:Cred } {
            Mock Connect-WoscapGmpStream { [pscustomobject]@{ Client = $null; Stream = [System.IO.MemoryStream]::new() } }
            Mock Send-WoscapGmpRequest { [xml]'<authenticate_response status="400" status_text="Authentication failed"/>' }
            $r = Invoke-WoscapOpenVasScan -Server 'gvm' -Credential $Cred -Targets @('h') -ScanConfigId 'c' -ScannerId 's' -PollSeconds 0 -WarningAction SilentlyContinue
            $r | Should -BeNullOrEmpty
        }
    }
    It 'warns and returns $null when a mid-flow step returns a 4xx status' {
        InModuleScope woscap -Parameters @{ Cred = $script:Cred } {
            Mock Connect-WoscapGmpStream { [pscustomobject]@{ Client = $null; Stream = [System.IO.MemoryStream]::new() } }
            Mock Send-WoscapGmpRequest {
                if ($Request -like '*<authenticate>*') { return [xml]'<authenticate_response status="200"/>' }
                if ($Request -like '*<create_target>*') { return [xml]'<create_target_response status="404" status_text="No such config"/>' }
                throw "should not reach: $Request"
            }
            $r = Invoke-WoscapOpenVasScan -Server 'gvm' -Credential $Cred -Targets @('h') -ScanConfigId 'c' -ScannerId 's' -PollSeconds 0 -WarningAction SilentlyContinue
            $r | Should -BeNullOrEmpty
        }
    }
    It 'warns and returns $null when the scan reaches a terminal failure state (does not hang)' {
        InModuleScope woscap -Parameters @{ Cred = $script:Cred } {
            Mock Connect-WoscapGmpStream { [pscustomobject]@{ Client = $null; Stream = [System.IO.MemoryStream]::new() } }
            Mock Start-Sleep {}
            Mock Send-WoscapGmpRequest {
                if ($Request -like '*<authenticate>*') { return [xml]'<authenticate_response status="200"/>' }
                if ($Request -like '*<create_target>*') { return [xml]'<create_target_response status="201" id="t"/>' }
                if ($Request -like '*<create_task>*')   { return [xml]'<create_task_response status="201" id="k"/>' }
                if ($Request -like '*<start_task*')      { return [xml]'<start_task_response status="202"><report_id>r</report_id></start_task_response>' }
                if ($Request -like '*<get_tasks*')       { return [xml]'<get_tasks_response status="200"><task id="k"><status>Stopped</status><progress>30</progress></task></get_tasks_response>' }
                if ($Request -like '*<delete_task*')     { return [xml]'<delete_task_response status="200"/>' }
                if ($Request -like '*<delete_target*')   { return [xml]'<delete_target_response status="200"/>' }
                throw "should not fetch report: $Request"
            }
            $r = Invoke-WoscapOpenVasScan -Server 'gvm' -Credential $Cred -Targets @('h') -ScanConfigId 'c' -ScannerId 's' -PollSeconds 0 -WarningAction SilentlyContinue
            $r | Should -BeNullOrEmpty
            Should -Invoke Send-WoscapGmpRequest -Times 0 -Exactly -ParameterFilter { $Request -like '*<get_reports*' }
        }
    }
    It 'warns and returns $null when the scan does not finish before the timeout' {
        InModuleScope woscap -Parameters @{ Cred = $script:Cred } {
            Mock Connect-WoscapGmpStream { [pscustomobject]@{ Client = $null; Stream = [System.IO.MemoryStream]::new() } }
            Mock Start-Sleep {}
            Mock Send-WoscapGmpRequest {
                if ($Request -like '*<authenticate>*') { return [xml]'<authenticate_response status="200"/>' }
                if ($Request -like '*<create_target>*') { return [xml]'<create_target_response status="201" id="t"/>' }
                if ($Request -like '*<create_task>*')   { return [xml]'<create_task_response status="201" id="k"/>' }
                if ($Request -like '*<start_task*')      { return [xml]'<start_task_response status="202"><report_id>r</report_id></start_task_response>' }
                if ($Request -like '*<get_tasks*')       { return [xml]'<get_tasks_response status="200"><task id="k"><status>Running</status><progress>10</progress></task></get_tasks_response>' }
                if ($Request -like '*<delete_task*')     { return [xml]'<delete_task_response status="200"/>' }
                if ($Request -like '*<delete_target*')   { return [xml]'<delete_target_response status="200"/>' }
                throw "should not fetch report: $Request"
            }
            $r = Invoke-WoscapOpenVasScan -Server 'gvm' -Credential $Cred -Targets @('h') -ScanConfigId 'c' -ScannerId 's' `
                    -PollSeconds 0 -TimeoutMinutes 0 -WarningAction SilentlyContinue
            $r | Should -BeNullOrEmpty
        }
    }
    It 'returns $null without sending when the connection fails' {
        InModuleScope woscap -Parameters @{ Cred = $script:Cred } {
            Mock Connect-WoscapGmpStream { $null }
            Mock Send-WoscapGmpRequest { throw 'must not be called' }
            $r = Invoke-WoscapOpenVasScan -Server 'gvm' -Credential $Cred -Targets @('h') -ScanConfigId 'c' -ScannerId 's' -PollSeconds 0
            $r | Should -BeNullOrEmpty
            Should -Invoke Send-WoscapGmpRequest -Times 0 -Exactly
        }
    }
    It 'warns and returns $null (no throw) when a reply has no status attribute' {
        InModuleScope woscap -Parameters @{ Cred = $script:Cred } {
            Mock Connect-WoscapGmpStream { [pscustomobject]@{ Client = $null; Stream = [System.IO.MemoryStream]::new() } }
            Mock Send-WoscapGmpRequest { [xml]'<html><body>Bad Gateway</body></html>' }
            $r = Invoke-WoscapOpenVasScan -Server 'gvm' -Credential $Cred -Targets @('h') -ScanConfigId 'c' -ScannerId 's' -PollSeconds 0 -WarningAction SilentlyContinue
            $r | Should -BeNullOrEmpty
        }
    }
}

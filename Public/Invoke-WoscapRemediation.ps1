function Invoke-WoscapRemediation {
    <#
    .SYNOPSIS
        Applies Registry and AuditPolicy fixes for Open STIG findings on the LOCAL host,
        then re-checks each rule. Gated by -WhatIf / -Confirm (ConfirmImpact High).
    .DESCRIPTION
        This is woscap's only deliberate write path. Requires an elevated session for
        real writes. Only Open findings are processed; every other status is ignored.

        Refuses to run from a 32-bit PowerShell on 64-bit Windows (WOW64), including with
        -WhatIf, because registry writes would land in the redirected 32-bit view.

        A Registry rule is auto-applied only when writing its Expected value is
        guaranteed to make the same rule pass:
          - Operator 'eq' with an Int32 Expected (written as REG_DWORD) or a string
            Expected (written as REG_SZ).
          - Operator 'ge' or 'le' with an Int32 Expected. The threshold itself is
            written, as REG_DWORD.
          - When the rule declares Kind = 'dword' or 'string', the value is written
            as that registry type (for example, the number 10 is written as the
            REG_SZ '10'). A Kind the value cannot be written as makes the rule Manual.
        An All rule whose every check is such a Registry value is fixed by writing
        each of those values, in order, under one confirmation. Every value is
        written, including one the rule only checks on some hosts (for example the
        Adobe Acrobat root, checked only when the unified app is installed). The
        writes stop at the first failure, and that row's Detail names the writes
        that succeeded, the one that failed and those not attempted. Any other
        composite (Any, nested, or with a non-Registry or non-automatable check)
        is reported as 'Manual'.
        These Registry rules are reported as 'Manual' and never written:
          - A path under HKCU. An elevated fix would write the operator's own hive,
            not the audited user's.
          - Any other operator (ne, in, notin, regex, sequence, exists, ...), or no
            Operator at all. None of these has one value woscap can safely choose.
          - An Expected that is not a string or an Int32 (an array, a boolean, a
            number outside the Int32 range, and so on).

        Any rule whose descriptor sets Remediate = $false is reported as 'Manual'
        and never written, with its RemediateReason in Detail. Content packs use
        this for rules that are Not Applicable on hosts woscap cannot identify (for
        example, the Defender Antivirus MAPS rules on classified systems).

        An AuditPolicy fix only ever enables auditing. It turns on the success
        and/or failure directions that the Open rules require, merged per
        subcategory, and never disables a direction.

        Every other check type (UserRight, Service, SecEdit, ScriptBlock, or a
        missing or incomplete descriptor) is reported as 'Manual' and never written.

        After a fix is applied, the rule's descriptor is evaluated again and the
        outcome is reported in After: NotAFinding, Open, or Error. If one fix fails,
        that row is reported as 'Failed' and the remaining fixes still run.
    .PARAMETER Result
        Findings to remediate, usually piped from Invoke-WoscapScan. Only rows with
        Status 'Open' are acted on; each row's StigId selects its content descriptor.
    .PARAMETER Benchmark
        Name of the shipped content pack under Content\ that supplies the fix
        descriptors. Default: Windows11. Ignored when -ContentPath is given.
    .PARAMETER ContentPath
        Directory of a content pack (checks.psd1, optional checks.overrides.ps1) to
        use instead of -Benchmark. The cmdlet throws if the path does not exist.
    .PARAMETER Force
        Apply without prompting, for unattended runs. An explicit -Confirm still
        prompts, and -WhatIf still only plans.
    .PARAMETER Quiet
        Suppress the console summary (Applied / Failed / Manual / Planned counts).
        The result objects are returned either way.
    .PARAMETER WhatIf
        Plan only. Every rule that would be auto-applied is returned with
        State 'Planned', and nothing is written. A multi-write fix lists every
        write in its Action.
    .PARAMETER Confirm
        Prompt before each write. Prompting is already the default because
        ConfirmImpact is High.
    .OUTPUTS
        RemediationResult objects (Host, StigId, StigIds, Title, CheckType, Action,
        State, Before, After, Detail). State is one of Applied, Failed, Manual,
        Planned (-WhatIf) or Skipped (declined at the prompt). For a Manual row,
        Detail gives the reason.
    .EXAMPLE
        Invoke-WoscapScan -XccdfPath .\U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml |
            Invoke-WoscapRemediation -WhatIf

        Shows what would change and writes nothing.
    .EXAMPLE
        $fixes = Invoke-WoscapScan -XccdfPath .\U_MS_Windows_11_STIG_V2R11_Manual-xccdf.xml |
            Invoke-WoscapRemediation -Force
        $fixes | Format-Table StigId, State, Before, After, Detail

        Applies every automatable fix without prompting (run from an elevated
        shell), then shows each rule's outcome.
    .EXAMPLE
        $scan | Invoke-WoscapRemediation -ContentPath .\MyPack

        Uses a custom content pack and prompts before each write.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] [AllowEmptyCollection()] [object[]] $Result,
        [string] $Benchmark = 'Windows11',
        [string] $ContentPath,
        [switch] $Force,
        [switch] $Quiet
    )
    begin {
        if (Test-WoscapWow64Process) { throw $script:WoscapWow64RefusalMessage }
        $buffer = [System.Collections.Generic.List[object]]::new()
    }
    process {
        foreach ($r in $Result) { if ($null -ne $r) { $buffer.Add($r) } }
    }
    end {
        if (-not $ContentPath) {
            $ContentPath = Join-Path $script:WoscapModuleRoot (Join-Path 'Content' $Benchmark)
        }
        if (-not (Test-Path -LiteralPath $ContentPath)) {
            throw "woscap: content pack path not found: $ContentPath"
        }
        $pack = Import-ContentPack -Path $ContentPath

        # -Force lowers the confirmation bar so ShouldProcess proceeds unattended.
        # An explicit -Confirm from the caller still wins (they asked to be prompted),
        # and -WhatIf always wins (plan only), so never override either.
        if ($Force -and -not $WhatIfPreference -and -not $PSBoundParameters.ContainsKey('Confirm')) { $ConfirmPreference = 'None' }

        $open = @($buffer | Where-Object { [string](Get-WoscapObjectProperty $_ 'Status') -eq 'Open' })
        $plan = Get-WoscapRemediationPlan -FailedRule $open -ContentPack $pack

        $results = [System.Collections.Generic.List[object]]::new()
        foreach ($action in $plan) {
            if ($action.Type -eq 'Manual') {
                $results.Add((New-WoscapRemediationResult -StigId $action.StigId -StigIds $action.StigIds -Title $action.Title `
                    -CheckType $action.CheckType -Action 'Manual remediation required' `
                    -State 'Manual' -Detail $action.ManualReason))
                continue
            }

            $summary = if ($action.Type -eq 'Registry') {
                @($action.Writes | ForEach-Object { "Set $($_.Path)\$($_.Name) = $($_.Data) ($($_.Kind))" }) -join '; '
            } else {
                "Enable audit '$($action.Audit.Subcategory)': $($action.Audit.Directions -join ' and ')"
            }

            if (-not $PSCmdlet.ShouldProcess("$env:COMPUTERNAME: $($action.StigId)", $summary)) {
                $state  = if ($WhatIfPreference) { 'Planned' } else { 'Skipped' }
                $detail = if ($WhatIfPreference) { 'WhatIf: not applied.' } else { 'Declined at confirmation prompt.' }
                $results.Add((New-WoscapRemediationResult -StigId $action.StigId -StigIds $action.StigIds -Title $action.Title `
                    -CheckType $action.CheckType -Action $summary -State $state -Detail $detail))
                continue
            }

            try {
                if ($action.Type -eq 'Registry') {
                    # In order, stopping at the first failure; the row names how far it got.
                    $writes = @($action.Writes)
                    for ($i = 0; $i -lt $writes.Count; $i++) {
                        $w = $writes[$i]
                        try {
                            Set-WoscapRegValue -Path $w.Path -Name $w.Name -Data $w.Data -Kind $w.Kind
                        } catch {
                            if ($writes.Count -eq 1) { throw }
                            $label = { param($x) "$($x.Path)\$($x.Name)" }
                            $done = @(if ($i -gt 0) { $writes[0..($i - 1)] | ForEach-Object { & $label $_ } })
                            $rest = @(if ($i -lt $writes.Count - 1) { $writes[($i + 1)..($writes.Count - 1)] | ForEach-Object { & $label $_ } })
                            $succeeded = if ($done.Count) { $done -join ', ' } else { 'none' }
                            $skipped = if ($rest.Count) { $rest -join ', ' } else { 'none' }
                            throw "Succeeded: $succeeded. Failed: $(& $label $w): $($_.Exception.Message). Not attempted: $skipped."
                        }
                    }
                } else {
                    $dirs = $action.Audit.Directions
                    Invoke-AuditPolSet -Subcategory $action.Audit.Subcategory `
                        -Success ([bool]($dirs -contains 'success')) -Failure ([bool]($dirs -contains 'failure'))
                }
                # Re-check the representative descriptor for this action (the subcategory's
                # first rule for audit; the whole rule, every write included, for registry).
                #
                # The read cache MUST be dropped first. secedit and auditpol
                # output is memoized for the life of a scan, so a re-check that
                # runs after our own write would otherwise replay the pre-fix
                # snapshot and report every applied fix as still Open.
                Clear-WoscapReadCache
                $descriptor = $pack[$action.StigId]
                $recheck = Test-Descriptor -Descriptor $descriptor
                $after = switch ([string]$recheck.Result) {
                    'Pass'  { 'NotAFinding' }
                    'Fail'  { 'Open' }
                    default { 'Error' }
                }
                $results.Add((New-WoscapRemediationResult -StigId $action.StigId -StigIds $action.StigIds -Title $action.Title `
                    -CheckType $action.CheckType -Action $summary -State 'Applied' -After $after -Detail ''))
            } catch {
                $results.Add((New-WoscapRemediationResult -StigId $action.StigId -StigIds $action.StigIds -Title $action.Title `
                    -CheckType $action.CheckType -Action $summary -State 'Failed' -Detail "$_"))
            }
        }

        if (-not $Quiet) {
            $applied = @($results | Where-Object { $_.State -eq 'Applied' }).Count
            $failed  = @($results | Where-Object { $_.State -eq 'Failed' }).Count
            $manual  = @($results | Where-Object { $_.State -eq 'Manual' }).Count
            $planned = @($results | Where-Object { $_.State -in @('Planned','Skipped') }).Count
            Write-Host ""
            Write-Host "woscap remediation - $env:COMPUTERNAME"
            Write-Host ("  Applied:  {0}" -f $applied)
            Write-Host ("  Failed:   {0}" -f $failed)
            Write-Host ("  Manual:   {0}" -f $manual)
            Write-Host ("  Planned:  {0}" -f $planned)
        }

        $results.ToArray()
    }
}

function Invoke-WoscapRemediation {
    <#
    .SYNOPSIS
        Applies Registry and AuditPolicy fixes for Open STIG findings on the LOCAL host,
        then re-checks each rule. Gated by -WhatIf / -Confirm (ConfirmImpact High).
    .DESCRIPTION
        This is woscap's only deliberate write path. Every other check type (UserRight,
        Service, SecEdit, ScriptBlock, missing/incomplete descriptor) is reported as
        'Manual' and never written. Requires an elevated session for real writes.
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
                $results.Add((New-WoscapRemediationResult -StigId $action.StigId -Title $action.Title `
                    -CheckType $action.CheckType -Action 'Manual remediation required' `
                    -State 'Manual' -Detail $action.ManualReason))
                continue
            }

            $summary = if ($action.Type -eq 'Registry') {
                "Set $($action.Registry.Path)\$($action.Registry.Name) = $($action.Registry.Data) ($($action.Registry.Kind))"
            } else {
                "Set audit '$($action.Audit.Subcategory)' = $($action.Audit.Directions -join ' and ')"
            }

            if (-not $PSCmdlet.ShouldProcess("$env:COMPUTERNAME: $($action.StigId)", $summary)) {
                $state  = if ($WhatIfPreference) { 'Planned' } else { 'Skipped' }
                $detail = if ($WhatIfPreference) { 'WhatIf: not applied.' } else { 'Declined at confirmation prompt.' }
                $results.Add((New-WoscapRemediationResult -StigId $action.StigId -Title $action.Title `
                    -CheckType $action.CheckType -Action $summary -State $state -Detail $detail))
                continue
            }

            try {
                if ($action.Type -eq 'Registry') {
                    Set-WoscapRegValue -Path $action.Registry.Path -Name $action.Registry.Name `
                        -Data $action.Registry.Data -Kind $action.Registry.Kind
                } else {
                    $dirs = $action.Audit.Directions
                    Invoke-AuditPolSet -Subcategory $action.Audit.Subcategory `
                        -Success ([bool]($dirs -contains 'success')) -Failure ([bool]($dirs -contains 'failure'))
                }
                # Re-check the representative descriptor for this action (the subcategory's
                # first rule for audit; the single rule for registry).
                $descriptor = $pack[$action.StigId]
                $recheck = Test-Descriptor -Descriptor $descriptor
                $after = switch ([string]$recheck.Result) {
                    'Pass'  { 'NotAFinding' }
                    'Fail'  { 'Open' }
                    default { 'Error' }
                }
                $results.Add((New-WoscapRemediationResult -StigId $action.StigId -Title $action.Title `
                    -CheckType $action.CheckType -Action $summary -State 'Applied' -After $after -Detail ''))
            } catch {
                $results.Add((New-WoscapRemediationResult -StigId $action.StigId -Title $action.Title `
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

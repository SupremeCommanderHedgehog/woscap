function Invoke-CheckEval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rules,
        [Parameter(Mandatory)] [hashtable] $ContentPack,
        [hashtable] $ExceptionProfile = @{},
        [string] $ComputerName = $env:COMPUTERNAME,
        [datetime] $ReferenceDate = (Get-Date)
    )
    # One scan, one set of readings. Cleared here rather than at the end so a
    # scan that throws part-way cannot leave a poisoned cache for the next one.
    Clear-WoscapReadCache

    $total = @($Rules).Count
    $index = 0
    foreach ($rule in $Rules) {
        $index++
        Write-Progress -Activity 'Evaluating STIG rules' -Status "$index of $total" `
            -PercentComplete ([int](($index / $total) * 100))
        $common = @{
            StigId           = $rule.StigId
            GroupId          = $rule.GroupId
            GroupTitle       = if ($rule.PSObject.Properties['GroupTitle']) { $rule.GroupTitle } else { $null }
            RuleId           = $rule.RuleId
            Cci              = $rule.Cci
            Title            = $rule.Title
            CheckText        = if ($rule.PSObject.Properties['CheckText'])  { $rule.CheckText }  else { $null }
            FixText          = if ($rule.PSObject.Properties['FixText'])     { $rule.FixText }    else { $null }
            Discussion       = if ($rule.PSObject.Properties['Discussion'])  { $rule.Discussion } else { $null }
            ComputerName     = $ComputerName
            Benchmark        = $rule.Benchmark
            BenchmarkVersion = $rule.BenchmarkVersion
        }

        $exception = if ([string]::IsNullOrEmpty($rule.StigId)) { $null } else {
            Resolve-WoscapException -StigId $rule.StigId -ExceptionProfile $ExceptionProfile -ReferenceDate $ReferenceDate
        }
        $exType    = if ($exception) { [string]$exception['Type'] } else { '' }
        $exRecord  = if ($exception) { New-WoscapExceptionRecord -Exception $exception } else { $null }
        $exJust    = if ($exception -and $exception.ContainsKey('Justification')) { [string]$exception['Justification'] } else { '' }
        $severity  = $rule.Severity
        if ($exType -eq 'Override' -and $exception.ContainsKey('Severity')) {
            $sev = [string]$exception['Severity']
            if ($sev -in 'high','medium','low') {
                $severity = $sev
            } else {
                Write-Warning "woscap: exception for $($rule.StigId) has invalid Severity '$sev'; keeping the rule's severity."
            }
        }

        if ($exType -eq 'NotApplicable') {
            New-WoscapResult @common -Severity $severity -Result 'NA' -Exception $exRecord -Comments $exJust `
                -FindingDetails 'Marked Not Applicable by exception profile.'
            continue
        }
        if ($exType -eq 'Exclude') {
            New-WoscapResult @common -Severity $severity -Result 'NotReviewed' -Exception $exRecord -Comments $exJust `
                -FindingDetails 'Excluded from evaluation by exception profile.'
            continue
        }

        if ([string]::IsNullOrEmpty($rule.StigId) -or -not $ContentPack.ContainsKey($rule.StigId)) {
            New-WoscapResult @common -Severity $severity -Result 'NotReviewed' -Exception $exRecord -Comments $exJust `
                -FindingDetails 'No automated check authored for this rule.'
            continue
        }

        $descriptor = $ContentPack[$rule.StigId]
        if ($exType -eq 'Override') {
            $descriptor = $descriptor.Clone()
            if ($exception.ContainsKey('Expected')) { $descriptor['Expected'] = $exception['Expected'] }
            if ($exception.ContainsKey('Operator')) { $descriptor['Operator'] = $exception['Operator'] }
        }

        $eval      = Test-Descriptor -Descriptor $descriptor
        $checkType = if ($descriptor.ContainsKey('Type')) { $descriptor['Type'] } else { $null }
        $details   = if ($checkType -eq 'Manual') {
            "Manual review required: $($eval.Expected) Evidence: [$($eval.Observed)]."
        } else {
            "Expected [$($eval.Expected)]; observed [$($eval.Observed)]."
        }

        New-WoscapResult @common -Severity $severity -Result $eval.Result -CheckType $checkType `
            -Expected $eval.Expected -Observed $eval.Observed -Exception $exRecord -Comments $exJust -FindingDetails $details
    }
    Write-Progress -Activity 'Evaluating STIG rules' -Completed
}

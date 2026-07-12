function Invoke-CheckEval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Rules,
        [Parameter(Mandatory)] [hashtable] $ContentPack,
        [string] $ComputerName = $env:COMPUTERNAME
    )
    foreach ($rule in $Rules) {
        $common = @{
            StigId           = $rule.StigId
            GroupId          = $rule.GroupId
            RuleId           = $rule.RuleId
            Cci              = $rule.Cci
            Severity         = $rule.Severity
            Title            = $rule.Title
            CheckText        = if ($rule.PSObject.Properties['CheckText'])  { $rule.CheckText }  else { $null }
            FixText          = if ($rule.PSObject.Properties['FixText'])     { $rule.FixText }    else { $null }
            Discussion       = if ($rule.PSObject.Properties['Discussion'])  { $rule.Discussion } else { $null }
            ComputerName     = $ComputerName
            Benchmark        = $rule.Benchmark
            BenchmarkVersion = $rule.BenchmarkVersion
        }

        if ([string]::IsNullOrEmpty($rule.StigId) -or -not $ContentPack.ContainsKey($rule.StigId)) {
            New-WoscapResult @common -Result 'NotReviewed' `
                -FindingDetails 'No automated check authored for this rule.'
            continue
        }

        $descriptor = $ContentPack[$rule.StigId]
        $eval = Test-Descriptor -Descriptor $descriptor
        $checkType = if ($descriptor.ContainsKey('Type')) { $descriptor.Type } else { $null }
        $details = "Expected [$($eval.Expected)]; observed [$($eval.Observed)]."

        New-WoscapResult @common -Result $eval.Result -CheckType $checkType `
            -Expected $eval.Expected -Observed $eval.Observed -FindingDetails $details
    }
}

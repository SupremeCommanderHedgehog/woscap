function Invoke-CompositeDescriptor {
    <#
    .SYNOPSIS
        Evaluate an All/Any descriptor over its child descriptors.
    .DESCRIPTION
        Children recurse through Test-Descriptor, so each may carry its own
        Type and its own Applicability.

        NA children are excluded from the verdict entirely: All passes when
        every non-NA child passes, Any passes when at least one non-NA child
        passes, and the composite is NA only when every child is NA. An Error
        in any child fails the composite and propagates its message, so a
        permission failure can never read as a pass.

        NotReviewed children are also excluded from the verdict, for the same
        reason as NA: they are not evidence either way. Counting one as
        non-passing made any All composite containing a Manual child report
        Fail on a compliant machine and buried the manual question. When every
        child is NA or NotReviewed the composite is NotReviewed - a human still
        has to answer - unless they are all NA, which stays NA.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Descriptor,
        [Parameter(Mandatory)] [ValidateSet('All','Any')] [string] $Mode
    )
    # @(if ...) not $x = if ... { @() }: an if-statement that outputs an empty
    # array assigns $null, and .Count on $null throws under StrictMode. That
    # would still surface as Error, but via an exception message rather than
    # the clear one below.
    $children = @(if ($Descriptor.ContainsKey('Checks')) { $Descriptor.Checks })
    if ($children.Count -eq 0) {
        return [pscustomobject]@{
            Result   = 'Error'
            Observed = "composite '$Mode' descriptor has no Checks"
            Expected = $null
        }
    }

    $results = @(foreach ($child in $children) { Test-Descriptor -Descriptor $child })

    # Neither NA nor NotReviewed is evidence, so neither votes on the verdict.
    $considered = @($results | Where-Object { $_.Result -notin @('NA','NotReviewed') })
    if ($considered.Count -eq 0) {
        $anyNotReviewed = @($results | Where-Object { $_.Result -eq 'NotReviewed' }).Count -gt 0
        return [pscustomobject]@{
            Result   = if ($anyNotReviewed) { 'NotReviewed' } else { 'NA' }
            Observed = (@($results | ForEach-Object { "$($_.Observed)" }) -join '; ')
            Expected = (@($results | ForEach-Object { "$($_.Expected)" } | Where-Object { $_ }) -join '; ')
        }
    }

    $errors = @($considered | Where-Object { $_.Result -eq 'Error' })
    if ($errors.Count -gt 0) {
        return [pscustomobject]@{
            Result   = 'Error'
            Observed = (@($errors | ForEach-Object { "$($_.Observed)" }) -join '; ')
            Expected = (@($considered | ForEach-Object { "$($_.Expected)" }) -join '; ')
        }
    }

    $passed = @($considered | Where-Object { $_.Result -eq 'Pass' }).Count
    $pass = if ($Mode -eq 'All') { $passed -eq $considered.Count } else { $passed -ge 1 }

    [pscustomobject]@{
        Result   = if ($pass) { 'Pass' } else { 'Fail' }
        Observed = (@($considered | ForEach-Object { "$($_.Observed)" }) -join '; ')
        Expected = (@($considered | ForEach-Object { "$($_.Expected)" }) -join '; ')
    }
}

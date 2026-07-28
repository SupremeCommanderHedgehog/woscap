function Test-Descriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Descriptor,
        # Read and report without rendering a verdict. Set only when evaluating
        # a Manual rule's Evidence child.
        [switch] $GatherOnly
    )

    # Applicability is resolved before any reading, so a rule that does not
    # apply costs nothing and can never produce a misleading Pass or Fail.
    if ($Descriptor.ContainsKey('Applicability')) {
        try {
            $applicability = Test-WoscapApplicability -Applicability $Descriptor.Applicability
        } catch {
            return [pscustomobject]@{ Result = 'Error'; Observed = "$_"; Expected = $null }
        }
        if ($applicability.Unreadable) {
            # Error, never NA: an NA drops the rule from the Open count, so an
            # unreadable gate would make an unevaluated control look compliant.
            return [pscustomobject]@{ Result = 'Error'; Observed = $applicability.Reason; Expected = $null }
        }
        if (-not $applicability.Applies) {
            return [pscustomobject]@{ Result = 'NA'; Observed = $applicability.Reason; Expected = $null }
        }
    }

    $expected = if ($Descriptor.ContainsKey('Expected')) { $Descriptor.Expected } else { $null }
    try {
        $observed = $null
        switch ($Descriptor.Type) {
            'Registry' {
                $observed = Get-RegValue -Path $Descriptor.Path -Name $Descriptor.Name
                # Rules worded "Value: 0 (or if the Value Name does not exist)"
                # treat a missing value as the compliant default.
                if ($null -eq $observed -and
                    $Descriptor.ContainsKey('AbsentIsPass') -and $Descriptor.AbsentIsPass) {
                    return [pscustomobject]@{ Result = 'Pass'; Observed = '<absent>'; Expected = $expected }
                }
            }
            'SecEdit' {
                $section = if ($Descriptor.ContainsKey('Section')) { $Descriptor.Section } else { 'System Access' }
                $observed = Get-SecEditSetting -Name $Descriptor.Name -Section $section
            }
            'UserRight' {
                $observedSids = @(Get-UserRight -Privilege $Descriptor.Privilege | ForEach-Object { $_ -replace '^\*', '' })
                $expectedSids = @()
                foreach ($principal in @($expected)) {
                    $sid = Resolve-PrincipalSid -Name $principal
                    if ([string]::IsNullOrEmpty($sid)) {
                        return [pscustomobject]@{ Result = 'Error'; Observed = ($observedSids -join ','); Expected = "unresolved principal: $principal" }
                    }
                    $expectedSids += $sid
                }
                $pass = Compare-WoscapValue -Operator $Descriptor.Operator -Observed $observedSids -Expected $expectedSids
                return [pscustomobject]@{
                    Result   = if ($pass) { 'Pass' } else { 'Fail' }
                    Observed = ($observedSids -join ',')
                    Expected = ($expectedSids -join ',')
                }
            }
            'AuditPolicy' {
                $observed = Get-AuditPolicy -Subcategory $Descriptor.Subcategory
            }
            'Service' {
                $property = if ($Descriptor.ContainsKey('Property')) { $Descriptor.Property } else { 'StartMode' }
                $observed = (Get-ServiceState -Name $Descriptor.Name).$property
            }
            'Cim' {
                $cimSplat = @{ ClassName = $Descriptor.ClassName; Property = $Descriptor.Property }
                if ($Descriptor.ContainsKey('Namespace')) { $cimSplat['Namespace'] = $Descriptor.Namespace }
                if ($Descriptor.ContainsKey('Filter'))    { $cimSplat['Filter']    = $Descriptor.Filter }
                $observed = Get-CimSetting @cimSplat
            }
            'Certificate' {
                # Observed is a match COUNT, so content reads 'ge 1' for
                # "must be present" and 'eq 0' for "must be absent".
                $certSplat = @{ Store = $Descriptor.Store; Match = $Descriptor.Match }
                if ($Descriptor.ContainsKey('RequireUnexpired') -and $Descriptor.RequireUnexpired) {
                    $certSplat['RequireUnexpired'] = $true
                }
                $certHits = Get-CertificateSetting @certSplat
                # Check the sentinel BEFORE counting. @(sentinel).Count is 1,
                # which would read as "one certificate matched" and pass every
                # must-be-present rule on a store that was never read. This is
                # the only type whose reading is transformed rather than passed
                # through, so it has to re-establish the invariant itself.
                if (Test-WoscapUnreadable -Value $certHits) { $observed = $certHits }
                else { $observed = @($certHits).Count }
            }
            'Acl' {
                # One descriptor may cover several paths, so WN11-00-000095
                # checks C:\, %ProgramFiles% and %SystemRoot% as one rule.
                $paths     = @($Descriptor.Path)
                $allowed   = if ($Descriptor.ContainsKey('AllowedPrincipals')) { @($Descriptor.AllowedPrincipals) } else { @() }
                $maxRights = if ($Descriptor.ContainsKey('MaxRights')) { @($Descriptor.MaxRights) } else { @() }
                $bad = foreach ($p in $paths) {
                    $verdict = Test-AclCompliance -Path $p -AllowedPrincipals $allowed -MaxRights $maxRights
                    if (-not $verdict.Compliant) { "$($p): $($verdict.Offenders)" }
                }
                $bad = @($bad | Where-Object { $null -ne $_ })
                return [pscustomobject]@{
                    Result   = if ($bad.Count -eq 0) { 'Pass' } else { 'Fail' }
                    Observed = if ($bad.Count -eq 0) { 'no non-privileged access' } else { $bad -join ' | ' }
                    Expected = "no access beyond [$($allowed -join ', ')] except [$($maxRights -join ', ')]"
                }
            }
            'OptionalFeature' {
                $observed = Get-OptionalFeatureState -FeatureName $Descriptor.FeatureName
            }
            'Path' {
                $observed = Test-PathPresence -Path $Descriptor.Path
            }
            'LocalAccount' {
                $laSplat = @{ Scope = $Descriptor.Scope; Property = $Descriptor.Property }
                if ($Descriptor.ContainsKey('Name'))          { $laSplat['Name']          = $Descriptor.Name }
                if ($Descriptor.ContainsKey('ThresholdDays')) { $laSplat['ThresholdDays'] = $Descriptor.ThresholdDays }
                $observed = Get-LocalAccountSetting @laSplat
            }
            'Manual' {
                # Always NotReviewed - a human must answer. Evidence, when the
                # descriptor declares it, is reported but never judged, so the
                # reviewer does not have to go read the setting themselves.
                $evidence = '<no automated evidence>'
                if ($Descriptor.ContainsKey('Evidence')) {
                    try {
                        $gathered = Test-Descriptor -Descriptor $Descriptor.Evidence -GatherOnly
                        $evidence = "$($gathered.Observed)"
                    } catch {
                        $evidence = "evidence unavailable: $_"
                    }
                }
                return [pscustomobject]@{
                    Result   = 'NotReviewed'
                    Observed = $evidence
                    Expected = $Descriptor.Question
                }
            }
            'All' { return Invoke-CompositeDescriptor -Descriptor $Descriptor -Mode 'All' }
            'Any' { return Invoke-CompositeDescriptor -Descriptor $Descriptor -Mode 'Any' }
            'ScriptBlock' {
                $sbResult = & $Descriptor.Script
                $sbStatus = [string]$sbResult
                if ($sbStatus -notin @('Pass','Fail','NA','NotReviewed','Error')) { $sbStatus = 'Error' }
                return [pscustomobject]@{ Result = $sbStatus; Observed = $sbResult; Expected = $null }
            }
            default {
                return [pscustomobject]@{ Result = 'Error'; Observed = $null; Expected = $expected }
            }
        }
        # A read that FAILED is never evidence. Mapping it to Error here is what
        # keeps every operator that treats "empty" as compliant - subsetof,
        # setequals @(), notin, exists:$false, AbsentIsPass - from scoring a
        # machine we could not read as compliant.
        if (Test-WoscapUnreadable -Value $observed) {
            return [pscustomobject]@{
                Result   = 'Error'
                Observed = (Get-WoscapUnreadableReason -Value $observed)
                Expected = $expected
            }
        }

        # Gather-only is an EXPLICIT mode, not an inference from a missing
        # Operator. Inferring it silently downgraded a typo'd or dropped
        # Operator key in a content pack from a loud Error to a NotReviewed
        # indistinguishable from "no check authored", excluding the rule from
        # the Open count and the compliance percentage.
        if ($GatherOnly) {
            return [pscustomobject]@{ Result = 'NotReviewed'; Observed = $observed; Expected = $expected }
        }
        if (-not $Descriptor.ContainsKey('Operator')) {
            return [pscustomobject]@{
                Result   = 'Error'
                Observed = "descriptor of Type '$($Descriptor.Type)' declares no Operator"
                Expected = $expected
            }
        }
        $pass = Compare-WoscapValue -Operator $Descriptor.Operator -Observed $observed -Expected $expected
        [pscustomobject]@{
            Result   = if ($pass) { 'Pass' } else { 'Fail' }
            Observed = $observed
            Expected = $expected
        }
    } catch {
        [pscustomobject]@{ Result = 'Error'; Observed = "$_"; Expected = $expected }
    }
}

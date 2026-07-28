function Test-WoscapDescriptorSchema {
    <#
    .SYNOPSIS
        Structurally validate one check descriptor. Returns a list of problem
        strings; an empty list means the descriptor is well-formed.
    .DESCRIPTION
        Structure only - it never reads the machine, so it is safe to run over
        an entire content pack in CI. Composite children are validated
        recursively, and the path to a failing child is included in the message.

        GatherOnly suppresses the Operator requirement. It is set when
        recursing into a Manual rule's Evidence, which is read and reported
        rather than judged. Content-pack entries always require an Operator.

        Problems are emitted enumerated rather than as a protected array: a
        protected empty array arrives at the caller as one object and would
        read as a single problem. Callers wrap the result in @().
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Descriptor,
        [string] $Context = 'descriptor',
        [switch] $GatherOnly
    )
    $problems = New-Object System.Collections.Generic.List[string]

    $requiredKeys = @{
        'Registry'        = @('Path','Name')
        'SecEdit'         = @('Name')
        'UserRight'       = @('Privilege')
        'AuditPolicy'     = @('Subcategory')
        'Service'         = @('Name')
        'Cim'             = @('ClassName','Property')
        'Certificate'     = @('Store','Match')
        'Acl'             = @('Path','AllowedPrincipals')
        'OptionalFeature' = @('FeatureName')
        'Path'            = @('Path')
        'LocalAccount'    = @('Scope','Property')
        'ScriptBlock'     = @('Script')
        'Manual'          = @('Question')
        'All'             = @('Checks')
        'Any'             = @('Checks')
    }
    # Types whose verdict comes from the type itself, not from Compare-WoscapValue.
    $noOperator = @('ScriptBlock','Manual','All','Any','Acl')
    $validOperators = @('eq','ne','ge','le','in','notin','includes','regex','exists','setequals','subsetof','supersetof','sequence')
    $validPredicates = @('DomainJoined','TpmPresent','CameraPresent','BluetoothPresent','HypervisorPresent','LocalAdminEnabled','OsBuildAtLeast','OsBuildBelow','RegistryValueEquals')

    if (-not $Descriptor.ContainsKey('Type') -or [string]::IsNullOrWhiteSpace([string]$Descriptor.Type)) {
        $problems.Add("$Context is missing Type")
        return $problems.ToArray()
    }
    $type = [string]$Descriptor.Type
    if (-not $requiredKeys.ContainsKey($type)) {
        $problems.Add("$Context has unknown Type '$type'")
        return $problems.ToArray()
    }

    foreach ($key in $requiredKeys[$type]) {
        if (-not $Descriptor.ContainsKey($key)) {
            $problems.Add("$Context of Type '$type' is missing required key '$key'")
        }
    }

    if ($type -notin $noOperator -and -not $GatherOnly) {
        if (-not $Descriptor.ContainsKey('Operator')) {
            $problems.Add("$Context of Type '$type' is missing Operator")
        } elseif ($validOperators -notcontains [string]$Descriptor.Operator) {
            $problems.Add("$Context has unknown Operator '$($Descriptor.Operator)'")
        }
    } elseif ($Descriptor.ContainsKey('Operator') -and $validOperators -notcontains [string]$Descriptor.Operator) {
        $problems.Add("$Context has unknown Operator '$($Descriptor.Operator)'")
    }

    # Cross-key validation. Required-key checks alone accept a LocalAccount
    # descriptor whose Scope and Property are individually valid but mutually
    # incompatible, which is a one-word typo away from a silent wrong verdict.
    if ($type -eq 'LocalAccount' -and $Descriptor.ContainsKey('Scope') -and $Descriptor.ContainsKey('Property')) {
        $validCombinations = @{
            'User'  = @('EnabledNames','NonExpiringNames','StaleNames','PasswordAgeDays')
            'Group' = @('Members')
        }
        $scope = [string]$Descriptor.Scope
        if ($validCombinations.ContainsKey($scope) -and
            $validCombinations[$scope] -notcontains [string]$Descriptor.Property) {
            $problems.Add("$Context has LocalAccount Scope '$scope' with incompatible Property '$($Descriptor.Property)'")
        }
        if ($scope -eq 'Group' -and -not $Descriptor.ContainsKey('Name')) {
            $problems.Add("$Context of Type 'LocalAccount' with Scope 'Group' is missing required key 'Name'")
        }
    }

    if ($Descriptor.ContainsKey('Applicability')) {
        if ($Descriptor.Applicability -isnot [hashtable]) {
            $problems.Add("$Context has a non-hashtable Applicability")
        } else {
            foreach ($predicate in @($Descriptor.Applicability.Keys)) {
                if ($validPredicates -notcontains [string]$predicate) {
                    $problems.Add("$Context has unknown applicability predicate '$predicate'")
                }
            }
        }
    }

    if ($type -in @('All','Any')) {
        # @(if ...) not $x = if ... { @() }: an if-statement that outputs an
        # empty array assigns $null, and .Count on $null throws under StrictMode.
        $children = @(if ($Descriptor.ContainsKey('Checks')) { $Descriptor.Checks })
        if ($children.Count -eq 0) {
            $problems.Add("$Context of Type '$type' has an empty Checks list")
        }
        $index = 0
        foreach ($child in $children) {
            if ($child -isnot [hashtable]) {
                $problems.Add("$Context child $index is not a hashtable")
            } else {
                foreach ($p in @(Test-WoscapDescriptorSchema -Descriptor $child -Context "$Context.Checks[$index]" -GatherOnly:$GatherOnly)) {
                    $problems.Add($p)
                }
            }
            $index++
        }
    }

    if ($type -eq 'Manual' -and $Descriptor.ContainsKey('Evidence')) {
        if ($Descriptor.Evidence -isnot [hashtable]) {
            $problems.Add("$Context has a non-hashtable Evidence")
        } else {
            foreach ($p in @(Test-WoscapDescriptorSchema -Descriptor $Descriptor.Evidence -Context "$Context.Evidence" -GatherOnly)) {
                $problems.Add($p)
            }
        }
    }

    $problems.ToArray()
}

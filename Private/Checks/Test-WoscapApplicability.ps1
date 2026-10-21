function Test-WoscapApplicability {
    <#
    .SYNOPSIS
        Decide whether a descriptor applies to this machine.
    .DESCRIPTION
        Resolves a fixed set of named predicates. Machine-observable conditions
        only - policy conditions a machine cannot know (classified network, PAW
        designation) belong in an exception profile, not here.

        An unrecognized predicate throws. Silently ignoring one would mark a
        rule applicable that its author meant to gate, or vice versa.

        RegistryValueEquals / RegistryValueIn make a rule NA only when the
        stored value matches AND its kind fits the gate values: integer gate
        values need a REG_DWORD, string gate values a REG_SZ or REG_EXPAND_SZ.
        Any other kind does not match, so the rule applies (never a false NA).

        Returns Applies, Reason, and Unreadable. When a predicate's underlying
        read fails, Unreadable is set and the caller must surface Error - NOT
        NA. Marking a rule NA on an unreadable fact drops it from scoring, so
        the host looks compliant on a control that was never evaluated.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Applicability)

    foreach ($name in @($Applicability.Keys)) {
        $arg = $Applicability[$name]
        switch ($name) {
            { $_ -in $script:WoscapBooleanFacts } {
                $fact = Get-WoscapMachineFact -Fact $name
                if (Test-WoscapUnreadable -Value $fact) {
                    return [pscustomobject]@{
                        Applies = $false; Unreadable = $true
                        Reason  = (Get-WoscapUnreadableReason -Value $fact)
                    }
                }
                $actual = [bool]$fact
                if ($actual -ne [bool]$arg) {
                    $label = switch ($name) {
                        'DomainJoined'      { if ($actual) { 'system is domain-joined' } else { 'system is not domain-joined' } }
                        'TpmPresent'        { if ($actual) { 'system has a TPM' }        else { 'system has no TPM' } }
                        'CameraPresent'     { if ($actual) { 'system has a camera' }     else { 'system has no camera' } }
                        'BluetoothPresent'  { if ($actual) { 'system has Bluetooth' }    else { 'system has no Bluetooth' } }
                        'HypervisorPresent' { if ($actual) { 'system has a hypervisor' } else { 'system has no hypervisor' } }
                        'LocalAdminEnabled' { if ($actual) { 'system has an enabled local administrator' } else { 'system has no enabled local administrator' } }
                        'AcrobatUnifiedApp' { if ($actual) { 'the unified Adobe Acrobat app is installed' } else { 'the unified Adobe Acrobat app is not installed' } }
                        default             { throw "woscap: no applicability label for fact '$name'." }
                    }
                    return [pscustomobject]@{ Applies = $false; Unreadable = $false; Reason = "Not applicable: $label." }
                }
                break
            }
            { $_ -in @('OsBuildAtLeast','OsBuildBelow') } {
                $buildFact = Get-WoscapMachineFact -Fact 'OsBuild'
                if (Test-WoscapUnreadable -Value $buildFact) {
                    return [pscustomobject]@{
                        Applies = $false; Unreadable = $true
                        Reason  = (Get-WoscapUnreadableReason -Value $buildFact)
                    }
                }
                $build = [int]$buildFact
                if ($name -eq 'OsBuildAtLeast' -and $build -lt [int]$arg) {
                    return [pscustomobject]@{ Applies = $false; Unreadable = $false; Reason = "Not applicable: OS build $build is below $arg." }
                }
                if ($name -eq 'OsBuildBelow' -and $build -ge [int]$arg) {
                    return [pscustomobject]@{ Applies = $false; Unreadable = $false; Reason = "Not applicable: OS build $build is $arg or later." }
                }
                break
            }
            { $_ -in @('RegistryValueEquals', 'RegistryValueIn') } {
                # Negative gate: the rule is Not Applicable WHEN the value matches.
                $entry = Get-RegValueEntry -Path $arg.Path -Name $arg.Name
                if (Test-WoscapUnreadable -Value $entry) {
                    return [pscustomobject]@{
                        Applies = $false; Unreadable = $true
                        Reason  = (Get-WoscapUnreadableReason -Value $entry)
                    }
                }
                $gateValues = @(if ($name -eq 'RegistryValueEquals') { $arg.Value } else { $arg.Values })
                # A wrong-kind value (REG_SZ "1" for an integer gate) never
                # matches, so it can never make a rule NA.
                $matched = $false
                if ($null -ne $entry -and $gateValues.Count -gt 0) {
                    $intGate = @($gateValues | Where-Object { -not (Test-WoscapIntegerValue $_) }).Count -eq 0
                    $strGate = @($gateValues | Where-Object { $_ -isnot [string] }).Count -eq 0
                    if ($intGate -and $entry.Kind -eq 'DWord') {
                        $matched = @($gateValues | ForEach-Object { [decimal]$_ }) -contains [decimal]$entry.Value
                    } elseif ($strGate -and $entry.Kind -in @('String', 'ExpandString')) {
                        $matched = $gateValues -contains [string]$entry.Value
                    }
                }
                if ($matched) {
                    return [pscustomobject]@{
                        Applies = $false; Unreadable = $false
                        Reason  = "Not applicable: $($arg.Path)\$($arg.Name) is $($entry.Value)."
                    }
                }
                break
            }
            default {
                throw "woscap: unknown applicability predicate '$name'."
            }
        }
    }
    [pscustomobject]@{ Applies = $true; Unreadable = $false; Reason = $null }
}

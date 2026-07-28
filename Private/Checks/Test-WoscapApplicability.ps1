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
            { $_ -in @('DomainJoined','TpmPresent','CameraPresent','BluetoothPresent','HypervisorPresent','LocalAdminEnabled') } {
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
                        'DomainJoined'      { if ($actual) { 'is domain-joined' } else { 'is not domain-joined' } }
                        'TpmPresent'        { if ($actual) { 'has a TPM' }        else { 'has no TPM' } }
                        'CameraPresent'     { if ($actual) { 'has a camera' }     else { 'has no camera' } }
                        'BluetoothPresent'  { if ($actual) { 'has Bluetooth' }    else { 'has no Bluetooth' } }
                        'HypervisorPresent' { if ($actual) { 'has a hypervisor' } else { 'has no hypervisor' } }
                        'LocalAdminEnabled' { if ($actual) { 'has an enabled local administrator' } else { 'has no enabled local administrator' } }
                    }
                    return [pscustomobject]@{ Applies = $false; Unreadable = $false; Reason = "Not applicable: system $label." }
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
            'RegistryValueEquals' {
                # Negative gate: the rule is Not Applicable WHEN the value matches.
                $observed = Get-RegValue -Path $arg.Path -Name $arg.Name
                if (Test-WoscapUnreadable -Value $observed) {
                    return [pscustomobject]@{
                        Applies = $false; Unreadable = $true
                        Reason  = (Get-WoscapUnreadableReason -Value $observed)
                    }
                }
                if ($null -ne $observed -and "$observed" -eq "$($arg.Value)") {
                    return [pscustomobject]@{
                        Applies = $false; Unreadable = $false
                        Reason  = "Not applicable: $($arg.Path)\$($arg.Name) is $($arg.Value)."
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

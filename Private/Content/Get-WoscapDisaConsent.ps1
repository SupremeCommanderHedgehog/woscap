function Test-WoscapHostInteractive {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    # Read-only probe, split out as its own function so tests can Mock it to force the
    # non-interactive branch of Get-WoscapDisaConsent without depending on the runner host.
    [Environment]::UserInteractive
}

function Get-WoscapDisaConsent {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Notice)

    # Read-only, mockable consent seam. Returns $true only if the operator interactively
    # accepts the DISA terms. Non-interactive hosts fail closed (return $false) so an
    # unattended run without -AcceptDisaTerms and without a marker never proceeds silently.
    if (-not (Test-WoscapHostInteractive)) { return $false }

    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Accept DISA terms and download'
    $no  = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'Do not download'
    $choices  = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

    # Fail closed if the host reports itself interactive but cannot actually service a prompt
    # (some CI agents / service / remoting hosts throw here). Returning $false lets the caller
    # surface the actionable "re-run with -AcceptDisaTerms" message instead of a raw HostException.
    try {
        $decision = $Host.UI.PromptForChoice('woscap: DISA STIG content', $Notice, $choices, 1)
    } catch {
        return $false
    }
    return ($decision -eq 0)
}

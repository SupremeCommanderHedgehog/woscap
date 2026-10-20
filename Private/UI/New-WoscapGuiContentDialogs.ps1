function Show-WoscapGuiDisaTermsDialog {
    <# Seam over the terms dialog: $null on cancel, else @{ Remember = [bool] }. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Notice)

    # Placeholder until the dialog lands; throwing keeps the terms gate fail-closed.
    throw 'woscap: the DISA terms dialog is not available yet.'
}

function Get-WoscapDisaNotice {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    # Single source for the DISA notice so the CLI prompt and the GUI terms dialog cannot diverge.
    @'
woscap does NOT bundle or redistribute DISA STIG content. This action downloads content
on demand from a URL you supply (or a bundled best-effort pointer) into an operator-local
cache. Your use of that content is governed by DISA's own terms (public.cyber.mil), not
this project.
'@
}

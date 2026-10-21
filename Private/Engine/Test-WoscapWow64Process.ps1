# Shared by every refusal point so the message cannot drift.
$script:WoscapWow64RefusalMessage = 'woscap: refusing to run from a 32-bit process on 64-bit Windows; registry and file reads and writes would be redirected (WOW64). Run 64-bit PowerShell (from a 32-bit host: %SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe).'

function Test-WoscapWow64Process {
    <#
    .SYNOPSIS
        True when this is a 32-bit process on 64-bit Windows (WOW64).
    .DESCRIPTION
        Under WOW64, HKLM\SOFTWARE and System32 are redirected to their 32-bit views, so a
        scan would read, and remediation would write, the wrong keys and files. x64 code
        emulated on ARM64 shares the native view and returns $false. This is the only
        place woscap reads process bitness; tests mock it.
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    [Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess
}

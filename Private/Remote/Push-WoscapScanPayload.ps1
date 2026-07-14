function Push-WoscapScanPayload {
    <#
        Ships the runtime-required woscap subset into a per-run temp dir on ONE
        already-open PSSession: creates $env:TEMP\woscap_<RunId> target-side and
        copies the manifest, root module, Private/ and Public/, plus the single
        content pack at -ContentPath into <runDir>\_content. Every remote path is
        derivable from RunId, so this returns nothing. Throws if a copy fails (the
        caller isolates that into a per-host staging error).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Session,
        [Parameter(Mandatory)] [string] $RunId,
        [Parameter(Mandatory)] [string] $ModuleRoot,
        [Parameter(Mandatory)] [string] $ContentPath
    )

    # 1. Create the per-run temp dir target-side (New-Item runs in the remote
    #    session, not on the audit host — see ReadOnly.Tests.ps1 whitelist).
    $runDir = Invoke-WoscapRemoteCommand -Session $Session -ArgumentList $RunId -ScriptBlock {
        param($runId)
        $p = Join-Path $env:TEMP ('woscap_' + $runId)
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        $p
    }

    # 2. Curated copy: manifest + root module + Private/ + Public/ into the run dir.
    Copy-WoscapModuleToSession -Session $Session -Path (Join-Path $ModuleRoot 'woscap.psd1') -Destination $runDir
    Copy-WoscapModuleToSession -Session $Session -Path (Join-Path $ModuleRoot 'woscap.psm1') -Destination $runDir
    Copy-WoscapModuleToSession -Session $Session -Path (Join-Path $ModuleRoot 'Private')     -Destination $runDir
    Copy-WoscapModuleToSession -Session $Session -Path (Join-Path $ModuleRoot 'Public')      -Destination $runDir

    # 3. Copy the single content pack into <runDir>\_content. Copy-Item -ToSession
    #    renames the source folder to a not-yet-existing _content, so the pack's
    #    files land directly under _content (a fixed path the scan block derives).
    Copy-WoscapModuleToSession -Session $Session -Path $ContentPath -Destination (Join-Path $runDir '_content')
}

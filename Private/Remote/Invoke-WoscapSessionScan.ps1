function Invoke-WoscapSessionScan {
    <#
        Runs a woscap evaluation inside ONE already-open PSSession:
        ships the module into a target temp dir, loads the content pack and
        runs the (private) engine target-side, returns that host's RuleResult[],
        and always removes the target temp dir. Throws if the remote work fails
        (the caller turns that into a host-level error result).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [object] $Session,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rules,
        [hashtable] $ExceptionProfile = @{},
        [Parameter(Mandatory)] [string] $ModuleRoot,
        [Parameter(Mandatory)] [string] $Benchmark,
        [Parameter(Mandatory)] [string] $ContentPath
    )

    # 1. Create a unique temp dir on the target and return its path.
    $remoteRoot = Invoke-WoscapRemoteCommand -Session $Session -ScriptBlock {
        $p = Join-Path $env:TEMP ('woscap_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        $p
    }

    try {
        # 2. Ship the module (incl. bundled Content/) into the target temp dir.
        Copy-WoscapModuleToSession -Session $Session -Path (Join-Path $ModuleRoot '*') -Destination $remoteRoot
        $manifest = Join-Path $remoteRoot 'woscap.psd1'

        # Resolve the pack path on the target. Bundled packs live under the copied
        # module tree; a custom ContentPath outside the module is copied separately.
        # Use StartsWith (not -like) so bracket/wildcard chars in the install path
        # do not break the prefix test.
        if ($ContentPath.StartsWith($ModuleRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            $rel      = $ContentPath.Substring($ModuleRoot.Length).TrimStart('\', '/')
            $packPath = Join-Path $remoteRoot $rel
        } else {
            # Copy-Item renames the source folder to _content, so the pack's files
            # land directly in _content -> that dir IS the pack path.
            $packPath = Join-Path $remoteRoot '_content'
            Copy-WoscapModuleToSession -Session $Session -Path $ContentPath -Destination $packPath
        }

        # 3. Import the module on the target and run the private engine in module scope.
        Invoke-WoscapRemoteCommand -Session $Session -ArgumentList $manifest, $packPath, $Rules, $ExceptionProfile -ScriptBlock {
            param($manifest, $packPath, $rules, $exceptions)
            Import-Module $manifest -Force
            & (Get-Module woscap) {
                param($packPath, $rules, $exceptions)
                # A zero-rule host is a clean no-op: Invoke-CheckEval's -Rules is a
                # mandatory [object[]] with no [AllowEmptyCollection()], so passing @()
                # would throw a binding error. Return nothing instead.
                if (@($rules).Count -eq 0) { return }
                $pack = Import-ContentPack -Path $packPath
                Invoke-CheckEval -Rules $rules -ContentPack $pack -ExceptionProfile $exceptions -ComputerName $env:COMPUTERNAME
            } $packPath $rules $exceptions
        }
    } finally {
        # 4. Always remove the target temp dir.
        Invoke-WoscapRemoteCommand -Session $Session -ArgumentList $remoteRoot -ScriptBlock {
            param($p) Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

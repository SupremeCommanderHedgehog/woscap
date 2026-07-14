function Import-WoscapPlugin {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)

    $knownHooks = Get-WoscapKnownHook

    try {
        $manifestPath = Join-Path $Path 'plugin.psd1'
        if (-not (Test-Path -LiteralPath $manifestPath)) {
            Write-Warning "woscap: plugin manifest not found: $manifestPath"; return
        }
        $manifest = Import-PowerShellDataFile -LiteralPath $manifestPath

        $name = if ($manifest.ContainsKey('Name')) { [string]$manifest.Name } else { '' }
        # Wrap the whole if-expression in @(): a single-element array returned from an
        # if/else block unrolls back to a scalar, and $scalar.Count throws under StrictMode.
        $caps = @(if ($manifest.ContainsKey('Capabilities')) { $manifest.Capabilities } else { @() })
        if ([string]::IsNullOrWhiteSpace($name) -or $caps.Count -eq 0) {
            Write-Warning "woscap: plugin at '$Path' has no Name or Capabilities."; return
        }

        $implFile = if ($manifest.ContainsKey('Implementation')) { [string]$manifest.Implementation } else { 'implementation.ps1' }
        $implPath = Join-Path $Path $implFile
        if (-not (Test-Path -LiteralPath $implPath)) {
            Write-Warning "woscap: plugin '$name' implementation not found: $implPath"; return
        }

        # Select the hashtable from the implementation's output so stray output
        # (Write-Output, etc.) emitted before the hashtable does not cause a wrongful reject.
        $out = @(& $implPath)
        $table = $out | Where-Object { $_ -is [hashtable] } | Select-Object -Last 1
        if ($null -eq $table -or $table -isnot [hashtable]) {
            Write-Warning "woscap: plugin '$name' implementation did not return a hashtable."; return
        }

        foreach ($cap in $caps) {
            if ($cap -notin $knownHooks) {
                Write-Warning "woscap: plugin '$name' declares unknown hook '$cap'."; return
            }
            if (-not $table.ContainsKey($cap)) {
                Write-Warning "woscap: plugin '$name' declares '$cap' but the implementation omits it."; return
            }
            if ($table[$cap] -isnot [scriptblock]) {
                Write-Warning "woscap: plugin '$name' hook '$cap' is not a scriptblock."; return
            }
        }
        foreach ($key in $table.Keys) {
            if ($key -notin $caps) {
                Write-Warning "woscap: plugin '$name' implements undeclared hook '$key'."; return
            }
        }

        [pscustomobject]@{
            Name         = $name
            Version      = if ($manifest.ContainsKey('Version')) { [string]$manifest.Version } else { '' }
            Description  = if ($manifest.ContainsKey('Description')) { [string]$manifest.Description } else { '' }
            Capabilities = $caps
            Hooks        = $table
            Path         = $Path
        }
    } catch {
        Write-Warning "woscap: failed to load plugin at '$Path': $_"; return
    }
}

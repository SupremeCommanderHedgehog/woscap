function Get-WoscapIntegration {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([string] $Path)

    $root = Get-WoscapPluginRoot -Path $Path
    if (-not (Test-Path -LiteralPath $root)) {
        Write-Warning "woscap: integrations path not found: $root"
        return
    }

    # If $root is itself a single plugin folder (contains plugin.psd1), enumerate
    # just that plugin; otherwise treat $root as a directory of plugin folders.
    $dirs = if (Test-Path -LiteralPath (Join-Path $root 'plugin.psd1')) {
        @(Get-Item -LiteralPath $root)
    } else {
        @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)
    }

    foreach ($dir in $dirs) {
        $manifestPath = Join-Path $dir.FullName 'plugin.psd1'
        if (-not (Test-Path -LiteralPath $manifestPath)) { continue }

        $loaded = Import-WoscapPlugin -Path $dir.FullName
        if ($loaded) {
            [pscustomobject]@{
                Name         = $loaded.Name
                Version      = $loaded.Version
                Capabilities = $loaded.Capabilities
                Conformant   = $true
                Path         = $loaded.Path
            }
        } else {
            $name = try { [string](Import-PowerShellDataFile -LiteralPath $manifestPath).Name } catch { '' }
            if ([string]::IsNullOrWhiteSpace($name)) { $name = $dir.Name }
            [pscustomobject]@{
                Name         = $name
                Version      = ''
                Capabilities = @()
                Conformant   = $false
                Path         = $dir.FullName
            }
        }
    }
}

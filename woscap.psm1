Set-StrictMode -Version Latest
# Absolute path to the module root, for resolving bundled Content/ packs.
$script:WoscapModuleRoot = $PSScriptRoot

$private = @( Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue )
$public  = @( Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public')  -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue )

foreach ($file in @($private + $public)) {
    try { . $file.FullName }
    catch { throw "Failed to import $($file.FullName): $_" }
}

# Export only the public functions by name. When there are none this exports
# nothing, and prevents the manifest's '*' from leaking Private helpers.
$publicNames = @($public | ForEach-Object { $_.BaseName })
Export-ModuleMember -Function $publicNames

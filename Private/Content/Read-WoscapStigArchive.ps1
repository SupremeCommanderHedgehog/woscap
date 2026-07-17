function Read-WoscapStigArchive {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $ZipPath)

    if (-not (Test-Path -LiteralPath $ZipPath)) {
        throw "woscap: archive not found: $ZipPath"
    }

    # Read-only: extract ONLY the manual XCCDF's text; never write to disk here.
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $entries = @($zip.Entries | Where-Object { $_.Name -like '*_Manual-xccdf.xml' })
        if ($entries.Count -eq 0) {
            throw "woscap: no *_Manual-xccdf.xml entry found in archive '$ZipPath'."
        }
        if ($entries.Count -gt 1) {
            throw "woscap: multiple *_Manual-xccdf.xml entries in archive '$ZipPath'; cannot disambiguate."
        }
        $entry  = $entries[0]
        $reader = New-Object System.IO.StreamReader($entry.Open())
        try { $xml = $reader.ReadToEnd() } finally { $reader.Dispose() }
        [pscustomobject]@{ FileName = $entry.Name; Xml = $xml }
    } finally {
        $zip.Dispose()
    }
}

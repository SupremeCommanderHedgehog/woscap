function New-WoscapContentSidecar {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Benchmark,
        [Parameter(Mandatory)] [string] $Revision,
        [string] $Title,
        [string] $SourceUrl,
        [string] $Etag,
        [string] $LastModified,
        [string] $ContentSha256
    )

    # Single source of truth for the .woscap-content.json sidecar shape, so the promote path
    # and the reuse/refresh path in Save-WoscapStigContent cannot drift field-for-field.
    # contentSha256 is the hash of the XCCDF content (the scanned document), not the archive.
    # Returns the JSON string; the caller writes it via Write-WoscapText.
    [pscustomobject]@{
        benchmark         = $Benchmark
        revision          = $Revision
        title             = $Title
        sourceUrl         = $SourceUrl
        retrievedRevision = $Revision
        etag              = $Etag
        lastModified      = $LastModified
        contentSha256     = $ContentSha256
    } | ConvertTo-Json
}

function Write-WoscapDisaTermsMarker {
    [CmdletBinding()]
    [OutputType([void])]
    param([Parameter(Mandatory)] [string] $CacheRoot)

    # Persist the interactive DISA-terms acknowledgement so later runs don't re-prompt. Called
    # from every Save-WoscapStigContent exit that completes work — the download/promote path AND
    # the ETag short-circuit — so a short-circuited run cannot silently drop a just-given consent.
    # Fail-closed: callers invoke this only after the operation has succeeded.
    $ack = [pscustomobject]@{
        acceptedDisaTerms = $true
        acceptedUtc       = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json
    Write-WoscapText -Text $ack -Path (Get-WoscapDisaMarkerPath -CacheRoot $CacheRoot)
}

function Get-WoscapStigDownloadPage {
    [CmdletBinding()]
    [OutputType([string])]
    param([string] $Uri = 'https://public.cyber.mil/stigs/downloads/')

    # Read-only network fetch of the public DISA downloads listing. Returns the raw HTML
    # string (not a parsed DOM): keeps the scrape resolver deterministic and headless-safe
    # (no MSHTML/ParsedHtml dependency) and makes the network call trivially mockable in tests.
    # -ErrorAction Stop so a transport failure fails closed rather than returning a partial page.
    $resp = Invoke-WebRequest -Uri $Uri -UseBasicParsing -ErrorAction Stop
    [string] $resp.Content
}

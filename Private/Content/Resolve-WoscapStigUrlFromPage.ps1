function Resolve-WoscapStigUrlFromPage {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Html,
        [Parameter(Mandatory)] [string] $Pattern
    )

    # Pure parser: no network. Extract each <a href="*.zip">text</a> (an optional ?query or
    # #fragment after .zip is tolerated, e.g. a CDN-versioned link), keep those whose text or href
    # matches $Pattern, parse a (Ver, Rel) tuple from the text (preferred) or the href filename, and
    # return the href with the highest (Ver, Rel). A matched link with no parseable revision is
    # skipped, not guessed. Warn + $null when nothing usable matches.
    if ([string]::IsNullOrWhiteSpace($Html)) {
        Write-Warning 'woscap: empty STIG downloads page; cannot resolve by scrape.'
        return $null
    }

    try { $null = [regex]::new($Pattern) } catch {
        Write-Warning "woscap: scrape pattern '$Pattern' is not a valid regex: $_"
        return $null
    }

    $anchor = [regex] '(?is)<a\b[^>]*\bhref\s*=\s*"([^"]+\.zip(?:[?#][^"]*)?)"[^>]*>(.*?)</a>'
    $bestUrl = $null; $bestVer = -1; $bestRel = -1

    foreach ($m in $anchor.Matches($Html)) {
        $href = $m.Groups[1].Value.Trim()
        $text = ($m.Groups[2].Value -replace '<[^>]+>', ' ').Trim()
        $haystack = "$text $href"
        if ($haystack -notmatch $Pattern) { continue }

        # Overflow-safe (Ver, Rel) parse: an out-of-Int32 digit run skips the row rather than
        # throwing out of the whole scrape (the parser's contract is warn+$null, never throw).
        $ver = 0; $rel = 0
        $ok = $false
        if ($text -match '(?i)Ver\s*(\d+)\s*,?\s*Rel\s*(\d+)') {
            $ok = [int]::TryParse($Matches[1], [ref] $ver) -and [int]::TryParse($Matches[2], [ref] $rel)
        } elseif ($href -match '(?i)V(\d+)R(\d+)') {
            $ok = [int]::TryParse($Matches[1], [ref] $ver) -and [int]::TryParse($Matches[2], [ref] $rel)
        }
        if (-not $ok) { continue }

        if ($ver -gt $bestVer -or ($ver -eq $bestVer -and $rel -gt $bestRel)) {
            $bestUrl = $href; $bestVer = $ver; $bestRel = $rel
        }
    }

    if (-not $bestUrl) {
        Write-Warning "woscap: no archive on the STIG downloads page matched pattern '$Pattern'."
        return $null
    }
    $bestUrl
}

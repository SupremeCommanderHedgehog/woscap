function ConvertTo-WoscapFlatCheckText {
    [CmdletBinding()]
    [OutputType([string])]
    param([string] $Text)

    # Normalize DISA check-content prose for regex extraction: collapse newlines/runs of whitespace
    # to single spaces and fold typographic (curly) quotes to straight ones. Shared by the pack
    # descriptor generators (ConvertTo-WoscapCheckDescriptor / ConvertTo-WoscapChromePolicyDescriptor)
    # so their parsing preamble cannot drift. Returns '' for null/empty input.
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $flat = ($Text -replace '\r?\n', ' ') -replace '\s+', ' '
    # Fold curly quotes to straight via regex \uXXXX escapes, NOT literal curly-quote bytes, so this
    # file stays pure ASCII and behaves identically on Windows PowerShell 5.1 (which reads a BOM-less
    # .ps1 as the system ANSI code page and would corrupt non-ASCII literals). U+201C/U+201D are the
    # curly double quotes; U+2018/U+2019 the curly single quotes.
    $flat -replace '[\u201C\u201D]', '"' -replace '[\u2018\u2019]', "'"
}

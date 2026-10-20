function Resolve-WoscapGuiDisaTerms {
    <#
        Decides whether a download/update may proceed and whether to pass -AcceptDisaTerms.
        Never writes the marker: the caller persists it only after the operation succeeds.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $CacheRoot)

    if (Test-WoscapDisaTermsAccepted -CacheRoot $CacheRoot) {
        return @{ Proceed = $true; AcceptSwitch = $false; Remember = $false }
    }
    # A failing dialog must never count as acceptance.
    try { $answer = Show-WoscapGuiDisaTermsDialog -Notice (Get-WoscapDisaNotice) } catch { $answer = $null }
    if ($null -eq $answer) {
        return @{ Proceed = $false; AcceptSwitch = $false; Remember = $false }
    }
    $remember = $false
    if ($answer -is [System.Collections.IDictionary] -and $answer.Contains('Remember')) { $remember = [bool]$answer['Remember'] }
    @{ Proceed = $true; AcceptSwitch = $true; Remember = $remember }
}

function Get-WoscapGuiRemoveScope {
    <# Splat for Remove-WoscapBenchmark; throws rather than ever yielding an empty Benchmark/Revision. #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] $Row, [switch] $AllRevisions)

    $get = {
        param($Name)
        $p = $Row.PSObject.Properties[$Name]
        if ($p -and $null -ne $p.Value) { ([string]$p.Value).Trim() } else { '' }
    }
    $benchmark = & $get 'Benchmark'
    if (-not $benchmark) { throw 'woscap: the selected row has no Benchmark; nothing to remove.' }
    if ($AllRevisions) { return @{ Benchmark = $benchmark } }
    $revision = & $get 'Revision'
    if (-not $revision) { throw "woscap: the selected row for '$benchmark' has no Revision; refusing to remove." }
    @{ Benchmark = $benchmark; Revision = $revision }
}

function Find-WoscapGuiContentPack {
    <# Exact, case-insensitive match of a cached benchmark name to a content pack; the pack's own name or $null. #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string] $Benchmark,
        [AllowNull()][AllowEmptyCollection()][string[]] $Available
    )
    if ([string]::IsNullOrWhiteSpace($Benchmark)) { return $null }
    foreach ($name in @($Available)) {
        if ($name -ieq $Benchmark.Trim()) { return $name }
    }
    $null
}

function Get-WoscapGuiContentDestination {
    <# Trimmed Cache folder text, or $null when blank (blank means the default cache root). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable] $Tag)
    $text = $Tag['ContentDestination'].Text
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $text.Trim()
}

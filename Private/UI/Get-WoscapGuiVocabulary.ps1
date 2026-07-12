function Get-WoscapGuiVocabulary {
    <#
        Derives the GUI dropdown vocabularies from their canonical owners so the dropdowns
        can never silently drift from the values the engine actually emits/accepts (#47):
          Severity <- New-WoscapResult   -Severity ValidateSet
          Format   <- Export-WoscapResult -Format   ValidateSet
          Status   <- the distinct display values ConvertTo-WoscapStatus can produce
        'All' is a GUI-only filter prefix the caller prepends; it is NOT part of these lists.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $validValues = {
        param($Command, $Parameter)
        $attr = (Get-Command $Command).Parameters[$Parameter].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
            Select-Object -First 1
        if ($attr) { @($attr.ValidValues) } else { @() }
    }

    $statusCodes = & $validValues 'ConvertTo-WoscapStatus' 'Result'
    $statuses = @($statusCodes | ForEach-Object { ConvertTo-WoscapStatus -Result $_ } | Select-Object -Unique)

    @{
        Severity = @(& $validValues 'New-WoscapResult'    'Severity')
        Format   = @(& $validValues 'Export-WoscapResult' 'Format')
        Status   = $statuses
    }
}

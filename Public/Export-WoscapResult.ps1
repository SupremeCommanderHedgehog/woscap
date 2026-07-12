function Export-WoscapResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] [object[]] $Result,
        [Parameter(Mandatory)] [ValidateSet('cklb','csv','json')] [string] $Format,
        [Parameter(Mandatory)] [string] $Path
    )
    begin { $all = [System.Collections.Generic.List[object]]::new() }
    process { foreach ($item in $Result) { $all.Add($item) } }
    end {
        $items = $all.ToArray()
        switch ($Format) {
            'cklb' { Export-WoscapCklb -Result $items -Path $Path }
            'csv'  { Export-WoscapCsv  -Result $items -Path $Path }
            'json' { Export-WoscapJson -Result $items -Path $Path }
        }
    }
}

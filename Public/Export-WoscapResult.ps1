function Export-WoscapResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] [object[]] $Result,
        [Parameter(Mandatory)] [ValidateSet('cklb','ckl','csv','html','json')] [string] $Format,
        [Parameter(Mandatory)] [string] $Path
    )
    begin { $all = [System.Collections.Generic.List[object]]::new() }
    process { foreach ($item in $Result) { $all.Add($item) } }
    end {
        $items = $all.ToArray()
        switch ($Format) {
            'ckl'  { Export-WoscapCkl  -Result $items -Path $Path }
            'cklb' { Export-WoscapCklb -Result $items -Path $Path }
            'csv'  { Export-WoscapCsv  -Result $items -Path $Path }
            'html' { Export-WoscapHtml -Result $items -Path $Path }
            'json' { Export-WoscapJson -Result $items -Path $Path }
        }
    }
}

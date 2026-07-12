function Export-WoscapHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Result,
        [Parameter(Mandatory)] [string] $Path
    )
    function Esc([object] $Text) { [System.Security.SecurityElement]::Escape([string]$Text) }

    $items     = @($Result)
    $benchmark = if ($items.Count) { [string]$items[0].Benchmark } else { 'woscap scan' }
    $hostName  = if ($items.Count) { [string]$items[0].Host }      else { '' }

    $statusCounts = @{}
    foreach ($s in 'NotAFinding','Open','Not_Applicable','Not_Reviewed') {
        $statusCounts[$s] = @($items | Where-Object Status -eq $s).Count
    }
    $openCat1 = @($items | Where-Object { $_.Status -eq 'Open' -and $_.Severity -eq 'high' }).Count
    $openCat2 = @($items | Where-Object { $_.Status -eq 'Open' -and $_.Severity -eq 'medium' }).Count
    $openCat3 = @($items | Where-Object { $_.Status -eq 'Open' -and $_.Severity -eq 'low' }).Count

    $rowLines = foreach ($r in $items) {
        $cls = switch ($r.Status) {
            'Open'           { 'st-open' }
            'NotAFinding'    { 'st-pass' }
            'Not_Applicable' { 'st-na' }
            default          { 'st-nr' }
        }
        "<tr class='$cls' data-status='$(Esc $r.Status)'><td>$(Esc $r.StigId)</td><td>$(Esc $r.Severity)</td><td>$(Esc $r.Status)</td><td>$(Esc $r.Title)</td></tr>"
    }
    $rows = $rowLines -join "`n"

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>woscap - $(Esc $benchmark)</title>
<style>
 body { font-family: Segoe UI, Arial, sans-serif; margin: 1.5rem; color: #1a1a1a; }
 h1 { font-size: 1.3rem; } .sub { color: #666; margin-bottom: 1rem; }
 .cards { display: flex; flex-wrap: wrap; gap: .6rem; margin-bottom: 1rem; }
 .card { border: 1px solid #ddd; border-radius: 6px; padding: .5rem .9rem; min-width: 7rem; }
 .card .n { font-size: 1.4rem; font-weight: 700; } .card .l { font-size: .75rem; color: #555; }
 input { padding: .4rem; width: 18rem; margin-bottom: .6rem; }
 table { border-collapse: collapse; width: 100%; font-size: .85rem; }
 th, td { border: 1px solid #e2e2e2; padding: .3rem .5rem; text-align: left; }
 th { background: #f4f4f4; cursor: default; }
 .st-open td { background: #fdecea; } .st-pass td { background: #eafaf0; }
 .st-na td { background: #eef2f7; } .st-nr td { background: #fff8e1; }
</style></head>
<body>
<h1>woscap compliance report - $(Esc $benchmark)</h1>
<div class="sub">Host: $(Esc $hostName) &middot; $($items.Count) rules</div>
<div class="cards">
 <div class="card"><div class="n">$($statusCounts['Open'])</div><div class="l">Open</div></div>
 <div class="card"><div class="n">$($statusCounts['NotAFinding'])</div><div class="l">NotAFinding</div></div>
 <div class="card"><div class="n">$($statusCounts['Not_Applicable'])</div><div class="l">Not_Applicable</div></div>
 <div class="card"><div class="n">$($statusCounts['Not_Reviewed'])</div><div class="l">Not_Reviewed</div></div>
 <div class="card"><div class="n">$openCat1</div><div class="l">Open CAT I</div></div>
 <div class="card"><div class="n">$openCat2</div><div class="l">Open CAT II</div></div>
 <div class="card"><div class="n">$openCat3</div><div class="l">Open CAT III</div></div>
</div>
<input id="q" type="text" placeholder="Filter rows..." onkeyup="woscapFilter()">
<table id="t"><thead><tr><th>STIG ID</th><th>Severity</th><th>Status</th><th>Title</th></tr></thead>
<tbody>
$rows
</tbody></table>
<script>
function woscapFilter() {
  var q = document.getElementById('q').value.toLowerCase();
  var rows = document.querySelectorAll('#t tbody tr');
  for (var i = 0; i < rows.length; i++) {
    rows[i].style.display = rows[i].innerText.toLowerCase().indexOf(q) > -1 ? '' : 'none';
  }
}
</script>
</body></html>
"@

    Write-WoscapText -Text $html -Path $Path
}

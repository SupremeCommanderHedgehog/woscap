function ConvertFrom-AnsibleInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [string] $Group
    )

    $lines = Get-Content -LiteralPath $Path
    $isYaml = ($Path -match '\.ya?ml$')

    $byGroup    = @{}   # group name -> list of hosts
    $childGroups = @{}  # group name -> list of child group names (from [g:children])

    if ($isYaml) {
        # Minimal parser for the standard inventory subset:
        #   all: > children: > <group>: > hosts: > <host>:
        $defaultGroup = 'all'
        $currentGroup = $null
        $inHosts = $false
        $hostIndent = $null   # indent of the 'hosts:' key currently in scope
        foreach ($raw in $lines) {
            if ($raw -match '^\s*#' -or $raw.Trim() -eq '') { continue }
            $indent = ($raw -replace '\S.*$', '').Length
            $token  = $raw.Trim().TrimEnd(':').Trim()
            # A 4-space-indented `<name>:` is a group header UNLESS we are inside a
            # `hosts:` block at a shallower indent, where such a line is a host entry
            # (as in the flat `all: > hosts: > <host>:` layout).
            if (-not ($inHosts -and $indent -gt $hostIndent) -and
                $raw -match '^\s{4}\S.*:\s*$' -and $token -notin @('hosts','children','vars')) {
                $currentGroup = $token; $byGroup[$currentGroup] = @(); $inHosts = $false; continue
            }
            if ($token -eq 'hosts') {
                $inHosts = $true
                $hostIndent = $indent
                # Hosts placed directly under `all: > hosts:` (no child group active)
                # belong to a synthetic default group so they are not dropped.
                if (-not $currentGroup) {
                    $currentGroup = $defaultGroup
                    if (-not $byGroup.ContainsKey($currentGroup)) { $byGroup[$currentGroup] = @() }
                }
                continue
            }
            if ($token -in @('children','vars')) { $inHosts = $false; continue }
            if ($inHosts -and $currentGroup -and $indent -gt $hostIndent) {
                # The host token is everything before the first ':'; anything after it
                # (e.g. "{ansible_host: 10.0.0.5}") is inline vars we discard.
                $hostName = (($raw.Trim() -split ':', 2)[0]).Trim()
                if ($hostName) { $byGroup[$currentGroup] += $hostName }
            }
        }
    } else {
        # INI: [group] headers; host is the first whitespace-delimited token per line.
        #   [group]          -> body lines are hosts
        #   [group:children] -> body lines are CHILD GROUP names (not hosts)
        #   [group:vars]     -> body lines are key=value vars (ignored)
        $currentGroup = $null
        $section = 'hosts'   # one of: hosts | children | vars
        foreach ($raw in $lines) {
            $line = $raw.Trim()
            if ($line -eq '' -or $line.StartsWith('#') -or $line.StartsWith(';')) { continue }
            if ($line -match '^\[(?<g>[^\]]+)\]$') {
                $header = $matches['g']
                if ($header -match '^(?<g>.+):(?<s>children|vars)$') {
                    $currentGroup = $matches['g']
                    $section = $matches['s']
                } else {
                    $currentGroup = $header
                    $section = 'hosts'
                }
                if (-not $byGroup.ContainsKey($currentGroup)) { $byGroup[$currentGroup] = @() }
                if (-not $childGroups.ContainsKey($currentGroup)) { $childGroups[$currentGroup] = @() }
                continue
            }
            if (-not $currentGroup) { continue }
            switch ($section) {
                'hosts'    { $byGroup[$currentGroup] += ($line -split '\s+')[0] }
                'children' { $childGroups[$currentGroup] += ($line -split '\s+')[0] }
                'vars'     { }   # ignored
            }
        }
    }

    # Recursively expand a group to its member hosts (own hosts + hosts of child groups).
    function Expand-Group {
        param([string] $Name, [System.Collections.Generic.HashSet[string]] $Seen)
        if (-not $Seen.Add($Name)) { return @() }   # guard against cycles
        $out = @()
        if ($byGroup.ContainsKey($Name)) { $out += $byGroup[$Name] }
        if ($childGroups.ContainsKey($Name)) {
            foreach ($child in $childGroups[$Name]) { $out += Expand-Group -Name $child -Seen $Seen }
        }
        $out
    }

    $selected = if ($Group) {
        Expand-Group -Name $Group -Seen ([System.Collections.Generic.HashSet[string]]::new())
    } else {
        # All hosts: union of every group's member hosts. Child-group NAMES never
        # appear because they are stored in $childGroups, not $byGroup.
        $byGroup.Values | ForEach-Object { $_ }
    }
    @($selected) | Where-Object { $_ } | Select-Object -Unique
}

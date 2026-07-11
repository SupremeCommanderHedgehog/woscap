# Scriptblock escape-hatch example. Returns one of Pass/Fail/NA/NotReviewed/Error.
@{
    # WN11-00-000170 (CAT II) — SMBv1 client (mrxsmb10) must be disabled (Start = 4).
    'WN11-00-000170' = @{
        Type   = 'ScriptBlock'
        Script = {
            $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start'
            if ($v -eq 4) { 'Pass' } else { 'Fail' }
        }
    }
}

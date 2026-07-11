@{
    # WN11-00-000165 (CAT II) — SMBv1 server driver must be disabled.
    'WN11-00-000165' = @{
        Type = 'Registry'
        Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        Name = 'SMB1'; Operator = 'eq'; Expected = 0
    }
    # WN11-00-000210 (CAT II) — Bluetooth must be turned off (device policy).
    'WN11-00-000210' = @{
        Type = 'Registry'
        Path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity'
        Name = 'AllowBluetooth'; Operator = 'eq'; Expected = 0
    }
    # WN11-AU-000500 (CAT II) — Application event log size must be >= 32768 KB.
    'WN11-AU-000500' = @{
        Type = 'Registry'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
        Name = 'MaxSize'; Operator = 'ge'; Expected = 32768
    }
}

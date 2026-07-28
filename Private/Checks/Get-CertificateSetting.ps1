function Get-WoscapCertStore {
    <#
    .SYNOPSIS
        Every certificate in a LocalMachine store, memoized per scan.
        Returns an empty set when the store cannot be read.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Store)
    Get-WoscapCachedValue -Key "cert:$Store" -Producer {
        try {
            ,@(Get-ChildItem -Path "Cert:\LocalMachine\$Store" -ErrorAction Stop)
        } catch {
            # NOT ,@(): an unreadable store must not read as "no certificates",
            # which would pass every must-be-absent check in the PK family.
            New-WoscapUnreadable -Reason "cannot read Cert:\LocalMachine\${Store}: $($_.Exception.Message)"
        }
    }
}

function Get-CertificateSetting {
    <#
    .SYNOPSIS
        Subjects of the certificates in a store matching every supplied criterion.
    .DESCRIPTION
        Match keys are Subject, Issuer, and Thumbprint; each value is a regex
        matched case-insensitively, and every supplied key must hold.

        RequireUnexpired is opt-in, not the default: WN11-PK-000015 and
        WN11-PK-000020 require specific cross-certificates to be present in the
        untrusted store even though their NotAfter has already passed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Store,
        [Parameter(Mandatory)] [hashtable] $Match,
        [switch] $RequireUnexpired
    )
    $store_ = Get-WoscapCertStore -Store $Store
    if (Test-WoscapUnreadable -Value $store_) { return $store_ }

    # An unrecognized Match key would otherwise set $ok=$false for every
    # certificate, yielding zero hits and passing a must-be-absent check.
    $knownFields = @('Subject','Issuer','Thumbprint')
    $unknown = @(@($Match.Keys) | Where-Object { $knownFields -notcontains [string]$_ })
    if ($unknown.Count -gt 0) {
        return New-WoscapUnreadable -Reason "unsupported certificate Match key(s): $($unknown -join ', ')"
    }

    $now = Get-Date
    $hits = foreach ($cert in @($store_)) {
        $ok = $true
        foreach ($field in @($Match.Keys)) {
            $value = switch ($field) {
                'Subject'    { [string]$cert.Subject }
                'Issuer'     { [string]$cert.Issuer }
                'Thumbprint' { [string]$cert.Thumbprint }
            }
            if ($null -eq $value -or $value -notmatch [string]$Match[$field]) { $ok = $false; break }
        }
        if ($ok -and $RequireUnexpired -and $cert.NotAfter -le $now) { $ok = $false }
        if ($ok) { [string]$cert.Subject }
    }
    # Emitted enumerated, not as ,@(...): the values are strings, so there is
    # no single-element array to protect, and wrapping an empty result would
    # make it arrive as one object and count as a match. Callers wrap in @().
    $hits | Where-Object { $null -ne $_ }
}

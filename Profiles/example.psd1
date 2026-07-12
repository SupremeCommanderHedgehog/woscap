# Example woscap exception profile. Keys are STIG IDs. Real DoD/commercial
# baselines are org-authored; this file demonstrates each exception type.
@{
    # Not applicable in this environment (documented).
    'WN11-00-000031' = @{ Type = 'NotApplicable'; Justification = 'No BitLocker in this environment.'; Author = 'example'; Date = '2026-07-01' }
    # Documented accepted risk (still reported Open with the justification).
    'WN11-00-000165' = @{ Type = 'AcceptedRisk';   Justification = 'Legacy app requires SMBv1; compensating controls in place.'; Author = 'example'; Date = '2026-07-01'; Expires = '2027-07-01' }
    # Org policy stricter than the STIG floor (re-evaluate + downgrade CAT).
    'WN11-AU-000500' = @{ Type = 'Override';        Justification = 'Org requires 64MB app log (or greater).'; Author = 'example'; Date = '2026-07-01'; Operator = 'ge'; Expected = 65536; Severity = 'low' }
    # Handled by a separate process, excluded from this scan.
    'WN11-00-000210' = @{ Type = 'Exclude';         Justification = 'Bluetooth governed by MDM, out of scope here.'; Author = 'example'; Date = '2026-07-01' }
}

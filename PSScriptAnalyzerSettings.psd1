@{
    # Lint woscap for Windows PowerShell 5.1 compatibility (the endpoint runtime).
    Severity = @('Error', 'Warning')

    IncludeRules = @('PSUseCompatibleSyntax', 'PSUseCompatibleCmdlets')

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            # 5.1 is the floor; 7.x listed so PS7-only syntax is flagged.
            TargetVersions = @('5.1', '7.4')
        }
    }

    # Use the default rule set in addition to the compatibility rules above.
    IncludeDefaultRules = $true
}

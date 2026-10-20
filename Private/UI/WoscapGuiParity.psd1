# Maps every public cmdlet parameter to the main-form Tag key that drives it (Control), or
# states why the GUI does not expose it (CliOnly). Enforced by tests/UI/WoscapGuiParity.Tests.ps1.
# Common parameters (incl. WhatIf/Confirm) are excluded; remediation's confirmation is the
# Remediate flow (Force -> Remediate); #17 adds entries for its own confirmations.
@{
    'Invoke-WoscapScan' = @{
        XccdfPath     = @{ Control = 'Xccdf' }
        Benchmark     = @{ Control = 'Benchmark' }
        ContentPath   = @{ Control = 'ContentPath' }
        ProfilePath   = @{ Control = 'Profiles' }
        ComputerName  = @{ Control = 'Targets' }
        Credential    = @{ Control = 'UseCred' }
        ThrottleLimit = @{ Control = 'ThrottleLimit' }
        JsonPath      = @{ Control = 'JsonPath' }
        Quiet         = @{ CliOnly = 'GUI always passes -Quiet; a console summary is meaningless in a window' }
    }
    'Export-WoscapResult' = @{
        Result = @{ Control = 'Grid' }
        Format = @{ Control = 'Format' }
        Path   = @{ CliOnly = 'Chosen per export in a save dialog' }
    }
    'Invoke-WoscapRemediation' = @{
        Result      = @{ Control = 'Grid' }
        Benchmark   = @{ Control = 'Benchmark' }
        ContentPath = @{ Control = 'ContentPath' }
        Force       = @{ Control = 'Remediate' }
        Quiet       = @{ CliOnly = 'GUI always passes -Quiet; the report dialog replaces the console summary' }
    }
    'Get-WoscapBenchmark' = @{
        Benchmark   = @{ CliOnly = 'Pending #17' }
        Destination = @{ CliOnly = 'Pending #17' }
    }
    'Save-WoscapStigContent' = @{
        Benchmark       = @{ CliOnly = 'Pending #17' }
        Url             = @{ CliOnly = 'Pending #17' }
        AcceptDisaTerms = @{ CliOnly = 'Pending #17' }
        Destination     = @{ CliOnly = 'Pending #17' }
        Force           = @{ CliOnly = 'Pending #17' }
        AllowScrape     = @{ CliOnly = 'Pending #17' }
    }
    'Update-WoscapBenchmark' = @{
        Benchmark       = @{ CliOnly = 'Pending #17' }
        Url             = @{ CliOnly = 'Pending #17' }
        AllowScrape     = @{ CliOnly = 'Pending #17' }
        AcceptDisaTerms = @{ CliOnly = 'Pending #17' }
        Destination     = @{ CliOnly = 'Pending #17' }
    }
    'Remove-WoscapBenchmark' = @{
        Benchmark   = @{ CliOnly = 'Pending #17' }
        Revision    = @{ CliOnly = 'Pending #17' }
        Destination = @{ CliOnly = 'Pending #17' }
    }
    'Get-WoscapIntegration' = @{
        Path = @{ CliOnly = 'Pending #18' }
    }
    'Invoke-WoscapIntegration' = @{
        Integration = @{ CliOnly = 'Pending #18' }
        Config      = @{ CliOnly = 'Pending #18' }
        PluginPath  = @{ CliOnly = 'Pending #18' }
    }
    'Import-WoscapIntegration' = @{
        Integration   = @{ CliOnly = 'Pending #18' }
        Targets       = @{ CliOnly = 'Pending #18' }
        Findings      = @{ CliOnly = 'Pending #18' }
        Source        = @{ CliOnly = 'Pending #18' }
        Path          = @{ CliOnly = 'Pending #18' }
        CorrelateWith = @{ CliOnly = 'Pending #18' }
        Config        = @{ CliOnly = 'Pending #18' }
        PluginPath    = @{ CliOnly = 'Pending #18' }
    }
    'Export-WoscapIntegration' = @{
        Integration = @{ CliOnly = 'Pending #18' }
        Result      = @{ CliOnly = 'Pending #18' }
        Remediation = @{ CliOnly = 'Pending #18' }
        Path        = @{ CliOnly = 'Pending #18' }
        Config      = @{ CliOnly = 'Pending #18' }
        PluginPath  = @{ CliOnly = 'Pending #18' }
    }
}

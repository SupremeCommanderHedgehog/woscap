# Maps every public cmdlet parameter to the main-form Tag key that drives it (Control), or
# states why the GUI does not expose it (CliOnly). Enforced by tests/UI/WoscapGuiParity.Tests.ps1.
# Common parameters (incl. WhatIf/Confirm) are excluded; remediation's confirmation is the
# Remediate flow (Force -> Remediate); content Update/Remove confirm in their own dialogs.
# GuiOnly is reserved, not a cmdlet: GUI items with no cmdlet parameter, Tag key -> reason.
@{
    'GuiOnly' = @{
        MenuResetSettings = 'File > Reset settings restores the GUI defaults and deletes the per-user GUI settings file; no cmdlet has GUI settings'
    }
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
        Benchmark   = @{ Control = 'ContentFilter' }
        Destination = @{ Control = 'ContentDestination' }
    }
    # Download dialog options; AcceptDisaTerms comes from the GUI terms dialog.
    'Save-WoscapStigContent' = @{
        Benchmark       = @{ Control = 'ContentDownload' }
        Url             = @{ Control = 'ContentDownload' }
        AcceptDisaTerms = @{ Control = 'ContentDownload' }
        Destination     = @{ Control = 'ContentDestination' }
        Force           = @{ Control = 'ContentDownload' }
        AllowScrape     = @{ Control = 'ContentDownload' }
    }
    'Update-WoscapBenchmark' = @{
        Benchmark       = @{ Control = 'ContentGrid' }
        Url             = @{ Control = 'ContentUpdate' }
        AllowScrape     = @{ Control = 'ContentUpdate' }
        AcceptDisaTerms = @{ Control = 'ContentUpdate' }
        Destination     = @{ Control = 'ContentDestination' }
    }
    'Remove-WoscapBenchmark' = @{
        Benchmark   = @{ Control = 'ContentRemove' }
        Revision    = @{ Control = 'ContentRemove' }
        Destination = @{ Control = 'ContentDestination' }
    }
    'Get-WoscapIntegration' = @{
        Path = @{ Control = 'IntegrationPath' }
    }
    # Each action's options come from the generated config form; PluginPath is the
    # selected plugin's folder when a Plugin folder is set.
    'Invoke-WoscapIntegration' = @{
        Integration = @{ Control = 'IntegrationGrid' }
        Config      = @{ Control = 'IntegrationRunScan' }
        PluginPath  = @{ Control = 'IntegrationPath' }
    }
    'Import-WoscapIntegration' = @{
        Integration   = @{ Control = 'IntegrationGrid' }
        Targets       = @{ Control = 'IntegrationImportTargets' }
        Findings      = @{ Control = 'IntegrationImportFindings' }
        Source        = @{ Control = 'IntegrationImportTargets' }
        Path          = @{ Control = 'IntegrationImportFindings' }
        CorrelateWith = @{ Control = 'IntegrationImportFindings' }
        Config        = @{ Control = 'IntegrationImportFindings' }
        PluginPath    = @{ Control = 'IntegrationPath' }
    }
    'Export-WoscapIntegration' = @{
        Integration = @{ Control = 'IntegrationGrid' }
        Result      = @{ Control = 'Grid' }
        Remediation = @{ Control = 'IntegrationExportRemediation' }
        Path        = @{ Control = 'IntegrationExportRemediation' }
        Config      = @{ Control = 'IntegrationExportFindings' }
        PluginPath  = @{ Control = 'IntegrationPath' }
    }
}
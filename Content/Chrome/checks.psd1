# Auto-generated from the DISA Google Chrome STIG V2R11 check-content (adversarially verified).
# Produced by ConvertTo-WoscapChromePolicyDescriptor over the Manual XCCDF. The Chrome STIG checks
# via chrome://policy and states no registry path; Chrome policies map deterministically to
# HKLM\SOFTWARE\Policies\Google\Chrome\<PolicyName>, so the policy name + required value come from
# the STIG and only that root is injected (REG_DWORD; false->0, true->1). List/allowlist,
# organization-specific string, multi-value, and version rules are omitted (engine: Not_Reviewed).
# NOT DISA content; verify against the official release before relying on results.
@{
    'DTBC-0001' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='RemoteAccessHostFirewallTraversal'; Operator='eq'; Expected=0 }
    'DTBC-0002' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='DefaultGeolocationSetting'; Operator='eq'; Expected=2 }
    'DTBC-0004' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='DefaultPopupsSetting'; Operator='eq'; Expected=2 }
    'DTBC-0009' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='DefaultSearchProviderEnabled'; Operator='eq'; Expected=1 }
    'DTBC-0011' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='PasswordManagerEnabled'; Operator='eq'; Expected=0 }
    'DTBC-0017' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='BackgroundModeEnabled'; Operator='eq'; Expected=0 }
    'DTBC-0020' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='SyncDisabled'; Operator='eq'; Expected=1 }
    'DTBC-0023' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='CloudPrintProxyEnabled'; Operator='eq'; Expected=0 }
    'DTBC-0025' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='NetworkPredictionOptions'; Operator='eq'; Expected=2 }
    'DTBC-0026' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='MetricsReportingEnabled'; Operator='eq'; Expected=0 }
    'DTBC-0027' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='SearchSuggestEnabled'; Operator='eq'; Expected=0 }
    'DTBC-0029' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='ImportSavedPasswords'; Operator='eq'; Expected=0 }
    'DTBC-0030' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='IncognitoModeAvailability'; Operator='eq'; Expected=1 }
    'DTBC-0037' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='EnableOnlineRevocationChecks'; Operator='eq'; Expected=1 }
    'DTBC-0039' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='SavingBrowserHistoryDisabled'; Operator='eq'; Expected=0 }
    'DTBC-0045' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='DefaultCookiesSetting'; Operator='eq'; Expected=4 }
    'DTBC-0052' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='AllowDeletingBrowserHistory'; Operator='eq'; Expected=0 }
    'DTBC-0053' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='PromptForDownloadLocation'; Operator='eq'; Expected=1 }
    'DTBC-0057' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='SafeBrowsingExtendedReportingEnabled'; Operator='eq'; Expected=0 }
    'DTBC-0058' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='DefaultWebUsbGuardSetting'; Operator='eq'; Expected=2 }
    'DTBC-0063' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='EnableMediaRouter'; Operator='eq'; Expected=0 }
    'DTBC-0064' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='AutoplayAllowed'; Operator='eq'; Expected=0 }
    'DTBC-0066' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='UrlKeyedAnonymizedDataCollectionEnabled'; Operator='eq'; Expected=0 }
    'DTBC-0067' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='WebRtcEventLogCollectionAllowed'; Operator='eq'; Expected=0 }
    'DTBC-0068' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='DeveloperToolsAvailability'; Operator='eq'; Expected=2 }
    'DTBC-0069' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='BrowserGuestModeEnabled'; Operator='eq'; Expected=0 }
    'DTBC-0070' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='AutofillCreditCardEnabled'; Operator='eq'; Expected=0 }
    'DTBC-0071' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='AutofillAddressEnabled'; Operator='eq'; Expected=0 }
    'DTBC-0072' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='ImportAutofillFormData'; Operator='eq'; Expected=0 }
    'DTBC-0073' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='DefaultWebBluetoothGuardSetting'; Operator='eq'; Expected=2 }
    'DTBC-0074' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='QuicAllowed'; Operator='eq'; Expected=0 }
    'DTBC-0075' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='CreateThemesSettings'; Operator='eq'; Expected=2 }
    'DTBC-0076' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='DevToolsGenAiSettings'; Operator='eq'; Expected=2 }
    'DTBC-0077' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='GenAILocalFoundationalModelSettings'; Operator='eq'; Expected=1 }
    'DTBC-0078' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='HelpMeWriteSettings'; Operator='eq'; Expected=2 }
    'DTBC-0079' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='HistorySearchSettings'; Operator='eq'; Expected=2 }
    'DTBC-0080' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Google\Chrome'; Name='TabCompareSettings'; Operator='eq'; Expected=2 }
}

# Auto-generated from the DISA Microsoft Edge STIG V2R5 check-content (adversarially verified).
# Produced by ConvertTo-WoscapCheckDescriptor over the Manual XCCDF: it emits a Registry descriptor
# only for rules that state a single scalar registry value inline. Non-registry / optional / manual
# rules (proxy JSON, search-engine lists, version cross-references) are omitted, so the engine
# reports them Not_Reviewed. NOT DISA content; verify against the official release before relying on
# results. Regenerate with a newer XCCDF when DISA publishes a new revision.
@{
    'EDGE-00-000002' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='PreventSmartScreenPromptOverride'; Operator='eq'; Expected=1 }
    'EDGE-00-000003' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='PreventSmartScreenPromptOverrideForFiles'; Operator='eq'; Expected=1 }
    'EDGE-00-000005' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='InPrivateModeAvailability'; Operator='eq'; Expected=1 }
    'EDGE-00-000006' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='BackgroundModeEnabled'; Operator='eq'; Expected=0 }
    'EDGE-00-000008' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='DefaultPopupsSetting'; Operator='eq'; Expected=2 }
    'EDGE-00-000010' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='SyncDisabled'; Operator='eq'; Expected=1 }
    'EDGE-00-000011' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='NetworkPredictionOptions'; Operator='eq'; Expected=2 }
    'EDGE-00-000012' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='SearchSuggestEnabled'; Operator='eq'; Expected=0 }
    'EDGE-00-000013' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ImportAutofillFormData'; Operator='eq'; Expected=0 }
    'EDGE-00-000014' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ImportBrowserSettings'; Operator='eq'; Expected=0 }
    'EDGE-00-000015' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ImportCookies'; Operator='eq'; Expected=0 }
    'EDGE-00-000016' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ImportExtensions'; Operator='eq'; Expected=0 }
    'EDGE-00-000017' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ImportHistory'; Operator='eq'; Expected=0 }
    'EDGE-00-000018' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ImportHomepage'; Operator='eq'; Expected=0 }
    'EDGE-00-000019' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ImportOpenTabs'; Operator='eq'; Expected=0 }
    'EDGE-00-000020' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ImportPaymentInfo'; Operator='eq'; Expected=0 }
    'EDGE-00-000021' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ImportSavedPasswords'; Operator='eq'; Expected=0 }
    'EDGE-00-000022' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ImportSearchEngine'; Operator='eq'; Expected=0 }
    'EDGE-00-000023' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ImportShortcuts'; Operator='eq'; Expected=0 }
    'EDGE-00-000024' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='AutoplayAllowed'; Operator='eq'; Expected=0 }
    'EDGE-00-000025' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='DefaultWebUsbGuardSetting'; Operator='eq'; Expected=2 }
    'EDGE-00-000026' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='EnableMediaRouter'; Operator='eq'; Expected=0 }
    'EDGE-00-000027' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='DefaultWebBluetoothGuardSetting'; Operator='eq'; Expected=2 }
    'EDGE-00-000028' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='AutofillCreditCardEnabled'; Operator='eq'; Expected=0 }
    'EDGE-00-000029' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='AutofillAddressEnabled'; Operator='eq'; Expected=0 }
    'EDGE-00-000030' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='EnableOnlineRevocationChecks'; Operator='eq'; Expected=1 }
    'EDGE-00-000031' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='PersonalizationReportingEnabled'; Operator='eq'; Expected=0 }
    'EDGE-00-000032' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='DefaultGeolocationSetting'; Operator='eq'; Expected=2 }
    'EDGE-00-000033' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='AllowDeletingBrowserHistory'; Operator='eq'; Expected=0 }
    'EDGE-00-000034' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='DeveloperToolsAvailability'; Operator='eq'; Expected=2 }
    'EDGE-00-000043' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='PasswordManagerEnabled'; Operator='eq'; Expected=0 }
    'EDGE-00-000047' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='SitePerProcess'; Operator='eq'; Expected=1 }
    'EDGE-00-000048' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='AuthSchemes'; Operator='eq'; Expected='ntlm,negotiate' }
    'EDGE-00-000050' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='SmartScreenEnabled'; Operator='eq'; Expected=1 }
    'EDGE-00-000051' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='SmartScreenPuaEnabled'; Operator='eq'; Expected=1 }
    'EDGE-00-000052' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='PromptForDownloadLocation'; Operator='eq'; Expected=1 }
    'EDGE-00-000054' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='TrackingPrevention'; Operator='eq'; Expected=2 }
    'EDGE-00-000055' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='PaymentMethodQueryEnabled'; Operator='eq'; Expected=0 }
    'EDGE-00-000056' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='AlternateErrorPagesEnabled'; Operator='eq'; Expected=0 }
    'EDGE-00-000057' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='UserFeedbackAllowed'; Operator='eq'; Expected=0 }
    'EDGE-00-000058' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='EdgeCollectionsEnabled'; Operator='eq'; Expected=0 }
    'EDGE-00-000059' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ConfigureShare'; Operator='eq'; Expected=1 }
    'EDGE-00-000060' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='BrowserGuestModeEnabled'; Operator='eq'; Expected=0 }
    'EDGE-00-000061' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='RelaunchNotification'; Operator='eq'; Expected=2 }
    'EDGE-00-000062' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='BuiltInDnsClientEnabled'; Operator='eq'; Expected=0 }
    'EDGE-00-000063' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='QuicAllowed'; Operator='eq'; Expected=0 }
    'EDGE-00-000065' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='VisualSearchEnabled'; Operator='eq'; Expected=0 }
    'EDGE-00-000066' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='HubsSidebarEnabled'; Operator='eq'; Expected=0 }
    'EDGE-00-000067' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='DefaultCookiesSetting'; Operator='eq'; Expected=4 }
    'EDGE-00-000068' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ConfigureFriendlyURLFormat'; Operator='eq'; Expected=1 }
    'EDGE-00-000069' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='ComposeInlineEnabled'; Operator='eq'; Expected=0 }
    'EDGE-00-000070' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Edge'; Name='MicrosoftEditorProofingEnabled'; Operator='eq'; Expected=0 }
}

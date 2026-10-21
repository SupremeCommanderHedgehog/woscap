# Adobe Acrobat Reader DC Continuous Track STIG V2R1 pack (23 Jul 2021). NOT DISA content; verify
# against the official release. Unified-app detection, the 000070 view choice, Manual rules and
# the #29 type exposure are documented in MANUAL.md, "Adobe Acrobat Reader DC pack".
@{
    'ARDC-CN-000005' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bEnhancedSecurityStandalone'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bEnhancedSecurityStandalone'; Operator = 'eq'; Expected = 1 }
    )}
    'ARDC-CN-000010' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bEnhancedSecurityInBrowser'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bEnhancedSecurityInBrowser'; Operator = 'eq'; Expected = 1 }
    )}
    'ARDC-CN-000015' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bProtectedMode'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bProtectedMode'; Operator = 'eq'; Expected = 1 }
    )}
    'ARDC-CN-000020' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'iProtectedView'; Operator = 'eq'; Expected = 2 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'iProtectedView'; Operator = 'eq'; Expected = 2 }
    )}
    # 0 is compliant only with a documented ISSO risk acceptance, which woscap cannot see.
    'ARDC-CN-000025' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms'; Name = 'iURLPerms'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cDefaultLaunchURLPerms'; Name = 'iURLPerms'; Operator = 'eq'; Expected = 1 }
    )
        Remediate = $false; RemediateReason = '0 is compliant with a documented ISSO risk acceptance, which woscap cannot detect' }
    'ARDC-CN-000030' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms'; Name = 'iUnknownURLPerms'; Operator = 'eq'; Expected = 3 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cDefaultLaunchURLPerms'; Name = 'iUnknownURLPerms'; Operator = 'eq'; Expected = 3 }
    )}
    'ARDC-CN-000035' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'iFileAttachmentPerms'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'iFileAttachmentPerms'; Operator = 'eq'; Expected = 1 }
    )}
    'ARDC-CN-000045' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bEnableFlash'; Operator = 'eq'; Expected = 0 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bEnableFlash'; Operator = 'eq'; Expected = 0 }
    )}
    'ARDC-CN-000050' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bDisablePDFHandlerSwitching'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bDisablePDFHandlerSwitching'; Operator = 'eq'; Expected = 1 }
    )}
    'ARDC-CN-000055' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud'; Name = 'bAdobeSendPluginToggle'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cCloud'; Name = 'bAdobeSendPluginToggle'; Operator = 'eq'; Expected = 1 }
    )}
    'ARDC-CN-000060' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bToggleAdobeDocumentServices'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices'; Name = 'bToggleAdobeDocumentServices'; Operator = 'eq'; Expected = 1 }
    )}
    'ARDC-CN-000065' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bTogglePrefsSync'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices'; Name = 'bTogglePrefsSync'; Operator = 'eq'; Expected = 1 }
    )}
    # DISA: "For 32 bit" the native key, "For 64 bit" Wow6432Node; unknown bitness fails.
    # A detected unified app also needs it in its Installer key: native when that exists, else Wow6432Node.
    'ARDC-CN-000070' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Cim'; ClassName = 'Win32_OperatingSystem'; Property = 'OSArchitecture'; Operator = 'regex'; Expected = '64' }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer'; Name = 'DisableMaintenance'; Operator = 'eq'; Expected = 1 }
            )}
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Cim'; ClassName = 'Win32_OperatingSystem'; Property = 'OSArchitecture'; Operator = 'regex'; Expected = '32' }
                @{ Type = 'Registry'; Path = 'HKLM:\Software\Adobe\Acrobat Reader\DC\Installer'; Name = 'DisableMaintenance'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'DisableMaintenance'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'DisableMaintenance'; Operator = 'eq'; Expected = 1 }
            )}
        )}
    )}
    'ARDC-CN-000075' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bToggleWebConnectors'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices'; Name = 'bToggleWebConnectors'; Operator = 'eq'; Expected = 1 }
    )}
    'ARDC-CN-000080' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bAcroSuppressUpsell'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bAcroSuppressUpsell'; Operator = 'eq'; Expected = 1 }
    )}
    'ARDC-CN-000085' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bToggleAdobeSign'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices'; Name = 'bToggleAdobeSign'; Operator = 'eq'; Expected = 1 }
    )}
    'ARDC-CN-000090' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles'; Name = 'bDisableWebmail'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cWebmailProfiles'; Name = 'bDisableWebmail'; Operator = 'eq'; Expected = 1 }
    )}
    # NA when configured to an approved DoD SharePoint server, which woscap cannot see.
    'ARDC-CN-000100' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint'; Name = 'bDisableSharePointFeatures'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cSharePoint'; Name = 'bDisableSharePointFeatures'; Operator = 'eq'; Expected = 1 }
    )
        Remediate = $false; RemediateReason = 'NA when configured to an approved DoD SharePoint server, which woscap cannot detect' }
    'ARDC-CN-000115' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen'; Name = 'bShowWelcomeScreen'; Operator = 'eq'; Expected = 0 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cWelcomeScreen'; Name = 'bShowWelcomeScreen'; Operator = 'eq'; Expected = 0 }
    )}
    'ARDC-CN-000120' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bUpdater'; Operator = 'eq'; Expected = 0 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices'; Name = 'bUpdater'; Operator = 'eq'; Expected = 0 }
    )}
    'ARDC-CN-000315' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bDisableTrustedFolders'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bDisableTrustedFolders'; Operator = 'eq'; Expected = 1 }
    )}
    'ARDC-CN-000320' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bDisableTrustedSites'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ AcrobatUnifiedApp = $true }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bDisableTrustedSites'; Operator = 'eq'; Expected = 1 }
    )}
    'ARDC-CN-000330' = @{ Type = 'Manual'
        Question = 'For every user profile that runs Adobe Reader DC, is bLoadSettingsFromURL = 0 (REG_DWORD) under HKCU\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\cEUTLDownload? Any other value, another type, or absence is a finding. On a unified-app host (64-bit Reader is the Acrobat app in Reader mode) the app reads HKCU\Software\Adobe\Adobe Acrobat\DC\Security\cDigSig\cEUTLDownload instead, so confirm the value there too. Evidence, in order, for the scanning account only: the Acrobat Reader value, then the Adobe Acrobat value.'
        Evidence = @{ Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKCU:\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\cEUTLDownload'; Name = 'bLoadSettingsFromURL'; Operator = 'exists'; Expected = $true }
            @{ Type = 'Registry'; Path = 'HKCU:\Software\Adobe\Adobe Acrobat\DC\Security\cDigSig\cEUTLDownload'; Name = 'bLoadSettingsFromURL'; Operator = 'exists'; Expected = $true }
        )} }
    'ARDC-CN-000335' = @{ Type = 'Manual'
        Question = 'For every user profile that runs Adobe Reader DC, is bLoadSettingsFromURL = 0 (REG_DWORD) under HKCU\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\cAdobeDownload? Any other value, another type, or absence is a finding. On a unified-app host (64-bit Reader is the Acrobat app in Reader mode) the app reads HKCU\Software\Adobe\Adobe Acrobat\DC\Security\cDigSig\cAdobeDownload instead, so confirm the value there too. Evidence, in order, for the scanning account only: the Acrobat Reader value, then the Adobe Acrobat value.'
        Evidence = @{ Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKCU:\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\cAdobeDownload'; Name = 'bLoadSettingsFromURL'; Operator = 'exists'; Expected = $true }
            @{ Type = 'Registry'; Path = 'HKCU:\Software\Adobe\Adobe Acrobat\DC\Security\cDigSig\cAdobeDownload'; Name = 'bLoadSettingsFromURL'; Operator = 'exists'; Expected = $true }
        )} }
    'ARDC-CN-000340' = @{ Type = 'Manual'
        Question = 'Open Adobe Acrobat Reader DC, Help > About Adobe Acrobat Reader DC. Are the latest security-related software updates by Adobe being applied (by WSUS, local procedure, auto update, etc.)? If not, this is a finding.' }
    'ARDC-CN-000345' = @{ Type = 'Manual'
        Question = 'For every user profile that runs Adobe Reader DC, is bFIPSMode = 1 (REG_DWORD) under HKCU\Software\Adobe\Acrobat Reader\DC\AVGeneral? Any other value, another type, or absence is a finding. On a unified-app host (64-bit Reader is the Acrobat app in Reader mode) the app reads HKCU\Software\Adobe\Adobe Acrobat\DC\AVGeneral instead, so confirm the value there too. Evidence, in order, for the scanning account only: the Acrobat Reader value, then the Adobe Acrobat value.'
        Evidence = @{ Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKCU:\Software\Adobe\Acrobat Reader\DC\AVGeneral'; Name = 'bFIPSMode'; Operator = 'exists'; Expected = $true }
            @{ Type = 'Registry'; Path = 'HKCU:\Software\Adobe\Adobe Acrobat\DC\AVGeneral'; Name = 'bFIPSMode'; Operator = 'exists'; Expected = $true }
        )} }
}

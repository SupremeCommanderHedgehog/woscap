# Adobe Acrobat Reader DC Continuous Track STIG V2R1 content pack (benchmark date 23 Jul 2021).
# NOT DISA content; verify against the official release before relying on results.
# Hand-authored from each rule's Manual XCCDF check-content; a wrong path or value here is
# a silent false Pass. No rule says absent is compliant, so a missing value is a finding.
#
# HKLM\SOFTWARE\Policies is shared between the 32- and 64-bit registry views, so the
# FeatureLockDown reads are view-independent. ARDC-CN-000070 names a view by OS bitness:
# Wow6432Node on 64-bit Windows, the native key on 32-bit; each branch is gated on
# Win32_OperatingSystem.OSArchitecture so the other view can never satisfy it.
#
# HKCU rules (000330/000335/000345) are Manual: HKCU is the scanning account's hive, not
# the Reader user's. 000340 (latest updates) is Manual. Not modelled (no machine fact):
# 000025 "0 with ISSO risk acceptance" and 000100 "NA with an approved DoD SharePoint
# server"; record those in an exception profile. Both opt out of automatic remediation.
# Comparisons ignore the registry value type (#29): DISA requires REG_DWORD, but a
# hand-edited REG_SZ "1" also passes here.
@{
    'ARDC-CN-000005' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bEnhancedSecurityStandalone'; Operator = 'eq'; Expected = 1 }
    'ARDC-CN-000010' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bEnhancedSecurityInBrowser'; Operator = 'eq'; Expected = 1 }
    'ARDC-CN-000015' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bProtectedMode'; Operator = 'eq'; Expected = 1 }
    'ARDC-CN-000020' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'iProtectedView'; Operator = 'eq'; Expected = 2 }
    # 0 is compliant only with a documented ISSO risk acceptance, which woscap cannot see.
    'ARDC-CN-000025' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms'; Name = 'iURLPerms'; Operator = 'eq'; Expected = 1
        Remediate = $false; RemediateReason = '0 is compliant with a documented ISSO risk acceptance, which woscap cannot detect' }
    'ARDC-CN-000030' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms'; Name = 'iUnknownURLPerms'; Operator = 'eq'; Expected = 3 }
    'ARDC-CN-000035' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'iFileAttachmentPerms'; Operator = 'eq'; Expected = 1 }
    'ARDC-CN-000045' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bEnableFlash'; Operator = 'eq'; Expected = 0 }
    'ARDC-CN-000050' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bDisablePDFHandlerSwitching'; Operator = 'eq'; Expected = 1 }
    'ARDC-CN-000055' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud'; Name = 'bAdobeSendPluginToggle'; Operator = 'eq'; Expected = 1 }
    'ARDC-CN-000060' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bToggleAdobeDocumentServices'; Operator = 'eq'; Expected = 1 }
    'ARDC-CN-000065' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bTogglePrefsSync'; Operator = 'eq'; Expected = 1 }
    # DISA: "For 32 bit" the native key, "For 64 bit" Wow6432Node. Unknown bitness fails.
    'ARDC-CN-000070' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'All'; Checks = @(
            @{ Type = 'Cim'; ClassName = 'Win32_OperatingSystem'; Property = 'OSArchitecture'; Operator = 'regex'; Expected = '64' }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer'; Name = 'DisableMaintenance'; Operator = 'eq'; Expected = 1 }
        )}
        @{ Type = 'All'; Checks = @(
            @{ Type = 'Cim'; ClassName = 'Win32_OperatingSystem'; Property = 'OSArchitecture'; Operator = 'regex'; Expected = '32' }
            @{ Type = 'Registry'; Path = 'HKLM:\Software\Adobe\Acrobat Reader\DC\Installer'; Name = 'DisableMaintenance'; Operator = 'eq'; Expected = 1 }
        )}
    )}
    'ARDC-CN-000075' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bToggleWebConnectors'; Operator = 'eq'; Expected = 1 }
    'ARDC-CN-000080' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bAcroSuppressUpsell'; Operator = 'eq'; Expected = 1 }
    'ARDC-CN-000085' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bToggleAdobeSign'; Operator = 'eq'; Expected = 1 }
    'ARDC-CN-000090' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles'; Name = 'bDisableWebmail'; Operator = 'eq'; Expected = 1 }
    # NA when configured to an approved DoD SharePoint server, which woscap cannot see.
    'ARDC-CN-000100' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint'; Name = 'bDisableSharePointFeatures'; Operator = 'eq'; Expected = 1
        Remediate = $false; RemediateReason = 'NA when configured to an approved DoD SharePoint server, which woscap cannot detect' }
    'ARDC-CN-000115' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen'; Name = 'bShowWelcomeScreen'; Operator = 'eq'; Expected = 0 }
    'ARDC-CN-000120' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bUpdater'; Operator = 'eq'; Expected = 0 }
    'ARDC-CN-000315' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bDisableTrustedFolders'; Operator = 'eq'; Expected = 1 }
    'ARDC-CN-000320' = @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bDisableTrustedSites'; Operator = 'eq'; Expected = 1 }
    'ARDC-CN-000330' = @{ Type = 'Manual'
        Question = 'For every user profile that runs Adobe Reader DC, is bLoadSettingsFromURL = 0 (REG_DWORD) under HKCU\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\cEUTLDownload? Any other value, another type, or absence is a finding. The evidence shown is the scanning account only.'
        Evidence = @{ Type = 'Registry'; Path = 'HKCU:\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\cEUTLDownload'; Name = 'bLoadSettingsFromURL' } }
    'ARDC-CN-000335' = @{ Type = 'Manual'
        Question = 'For every user profile that runs Adobe Reader DC, is bLoadSettingsFromURL = 0 (REG_DWORD) under HKCU\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\cAdobeDownload? Any other value, another type, or absence is a finding. The evidence shown is the scanning account only.'
        Evidence = @{ Type = 'Registry'; Path = 'HKCU:\Software\Adobe\Acrobat Reader\DC\Security\cDigSig\cAdobeDownload'; Name = 'bLoadSettingsFromURL' } }
    'ARDC-CN-000340' = @{ Type = 'Manual'
        Question = 'Open Adobe Acrobat Reader DC, Help > About Adobe Acrobat Reader DC. Are the latest security-related software updates by Adobe being applied (by WSUS, local procedure, auto update, etc.)? If not, this is a finding.' }
    'ARDC-CN-000345' = @{ Type = 'Manual'
        Question = 'For every user profile that runs Adobe Reader DC, is bFIPSMode = 1 (REG_DWORD) under HKCU\Software\Adobe\Acrobat Reader\DC\AVGeneral? Any other value, another type, or absence is a finding. The evidence shown is the scanning account only.'
        Evidence = @{ Type = 'Registry'; Path = 'HKCU:\Software\Adobe\Acrobat Reader\DC\AVGeneral'; Name = 'bFIPSMode' } }
}

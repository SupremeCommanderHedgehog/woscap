# Adobe Acrobat Reader DC Continuous Track STIG V2R1 content pack (benchmark date 23 Jul 2021).
# NOT DISA content; verify against the official release before relying on results.
# Hand-authored from each rule's Manual XCCDF check-content; a wrong path or value here is
# a silent false Pass. No rule says absent is compliant, so a missing value is a finding.
#
# Unified app: 64-bit Reader is the single Acrobat app in Reader mode, which reads the
# "Adobe Acrobat\DC" root, not DISA's "Acrobat Reader\DC" (Adobe single-installer guide).
# Each rule requires DISA's literal value and, when an "Adobe Acrobat\DC\Installer" key
# exists in either view, the same value under the Adobe Acrobat root too. The key test
# plus an Is64BitProduct read fail closed: unreadable is Error. Acrobat Pro alongside a
# classic Reader also triggers it (a possible false Open, never a false Pass).
#
# HKLM\SOFTWARE\Policies is shared by both registry views. ARDC-CN-000070 names a view by
# OS bitness, gated on Win32_OperatingSystem.OSArchitecture.
#
# Every rule is a composite, so remediation reports all of them Manual: no single write
# provably passes on every host. HKCU rules (000330/000335/000345) and 000340 are Manual.
# Not modelled: 000025 "0 with ISSO risk acceptance" and 000100 "NA with an approved DoD
# SharePoint server"; record those in an exception profile.
#
# Comparisons ignore the registry value type (#29). DISA requires REG_DWORD, but these also
# pass: REG_SZ exactly the digit, REG_QWORD, REG_MULTI_SZ containing it, REG_BINARY with a
# byte equal to it (two zero bytes for Expected 0). Needs a hand edit; GPO writes DWORD.
@{
    'ARDC-CN-000005' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bEnhancedSecurityStandalone'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bEnhancedSecurityStandalone'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000010' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bEnhancedSecurityInBrowser'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bEnhancedSecurityInBrowser'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000015' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bProtectedMode'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bProtectedMode'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000020' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'iProtectedView'; Operator = 'eq'; Expected = 2 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'iProtectedView'; Operator = 'eq'; Expected = 2 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    # 0 is compliant only with a documented ISSO risk acceptance, which woscap cannot see.
    'ARDC-CN-000025' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms'; Name = 'iURLPerms'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cDefaultLaunchURLPerms'; Name = 'iURLPerms'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )
        Remediate = $false; RemediateReason = '0 is compliant with a documented ISSO risk acceptance, which woscap cannot detect' }
    'ARDC-CN-000030' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cDefaultLaunchURLPerms'; Name = 'iUnknownURLPerms'; Operator = 'eq'; Expected = 3 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cDefaultLaunchURLPerms'; Name = 'iUnknownURLPerms'; Operator = 'eq'; Expected = 3 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000035' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'iFileAttachmentPerms'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'iFileAttachmentPerms'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000045' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bEnableFlash'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bEnableFlash'; Operator = 'eq'; Expected = 0 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000050' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bDisablePDFHandlerSwitching'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bDisablePDFHandlerSwitching'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000055' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud'; Name = 'bAdobeSendPluginToggle'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cCloud'; Name = 'bAdobeSendPluginToggle'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000060' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bToggleAdobeDocumentServices'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices'; Name = 'bToggleAdobeDocumentServices'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000065' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bTogglePrefsSync'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices'; Name = 'bTogglePrefsSync'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    # DISA: "For 32 bit" the native key, "For 64 bit" Wow6432Node; unknown bitness fails.
    # The unified app also needs DisableMaintenance in its own Installer key.
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
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'DisableMaintenance'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000075' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bToggleWebConnectors'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices'; Name = 'bToggleWebConnectors'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000080' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bAcroSuppressUpsell'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bAcroSuppressUpsell'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000085' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bToggleAdobeSign'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices'; Name = 'bToggleAdobeSign'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000090' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWebmailProfiles'; Name = 'bDisableWebmail'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cWebmailProfiles'; Name = 'bDisableWebmail'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    # NA when configured to an approved DoD SharePoint server, which woscap cannot see.
    'ARDC-CN-000100' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cSharePoint'; Name = 'bDisableSharePointFeatures'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cSharePoint'; Name = 'bDisableSharePointFeatures'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )
        Remediate = $false; RemediateReason = 'NA when configured to an approved DoD SharePoint server, which woscap cannot detect' }
    'ARDC-CN-000115' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cWelcomeScreen'; Name = 'bShowWelcomeScreen'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cWelcomeScreen'; Name = 'bShowWelcomeScreen'; Operator = 'eq'; Expected = 0 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000120' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cServices'; Name = 'bUpdater'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices'; Name = 'bUpdater'; Operator = 'eq'; Expected = 0 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000315' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bDisableTrustedFolders'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bDisableTrustedFolders'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
    )}
    'ARDC-CN-000320' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'; Name = 'bDisableTrustedSites'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown'; Name = 'bDisableTrustedSites'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Operator = 'eq'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer'; Name = 'Is64BitProduct'; Operator = 'exists'; Expected = $false }
            )}
        )}
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

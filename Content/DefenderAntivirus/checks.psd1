# Microsoft Defender Antivirus STIG V2R10 content pack (benchmark date 30 Sep 2026).
# NOT DISA content; verify against the official release before relying on results.
# Hand-authored from each rule's Manual XCCDF check-content; a wrong path or value
# here is a silent false Pass.
#
# AbsentIsPass only where the check-content says "If the value does not exist, this
# is not a finding". Everywhere else a missing value is a finding.
#
# "Alternate Check (if Microsoft Intune applied this setting)" reads the
# ...\Windows Defender\Policy Manager value only when the GPO value is absent:
# Any(GPO ok, All(GPO absent, Intune ok)), so a present non-compliant GPO value
# can never be outvoted by a compliant Intune value. Where one GPO value is the
# only compliant one, the fallback is gated NA when the GPO value already
# matches, so an unreadable Policy Manager key (non-elevated scan) cannot turn
# a compliant GPO into Error. NA never votes Pass in a composite.
#
# Not modelled (no machine fact): "NA for classified systems" (000008-000011) and
# "NA if third-party antivirus is installed" (000028/000029). Record those NAs in an
# exception profile. "NA before Windows 10 v1709" uses OsBuildAtLeast 16299.
@{
    'WNDF-AV-000001' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Name = 'PUAProtection'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ RegistryValueEquals = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Name = 'PUAProtection'; Value = 1 } }; Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Name = 'PUAProtection'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'; Name = 'PUAProtection'; Operator = 'eq'; Expected = 1 }
        )}
    )}
    'WNDF-AV-000003' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Name = 'DisableRoutinelyTakingAction'; Operator = 'eq'; Expected = 0; AbsentIsPass = $true }
    # "Not Configured" is the only compliant state, so any value present is a finding.
    'WNDF-AV-000004' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Name = 'DisableAntiSpyware'; Operator = 'exists'; Expected = $false }
    # Only absence is stated as compliant; a "Disabled" policy value reads Open (never a false Pass).
    'WNDF-AV-000005' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'; Name = 'Exclusions_Paths'; Operator = 'exists'; Expected = $false }
    'WNDF-AV-000006' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'; Name = 'Exclusions_Processes'; Operator = 'exists'; Expected = $false }
    'WNDF-AV-000007' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'; Name = 'DisableAutoExclusions'; Operator = 'eq'; Expected = 0 }
    'WNDF-AV-000008' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'; Name = 'LocalSettingOverrideSpynetReporting'; Operator = 'eq'; Expected = 0; AbsentIsPass = $true }
    'WNDF-AV-000009' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'; Name = 'DisableBlockAtFirstSeen'; Operator = 'eq'; Expected = 0 }
    'WNDF-AV-000010' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'; Name = 'SpynetReporting'; Operator = 'in'; Expected = @(1, 2) }
    'WNDF-AV-000011' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'; Name = 'SubmitSamplesConsent'; Operator = 'eq'; Expected = 1 }
    'WNDF-AV-000012' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS'; Name = 'DisableProtocolRecognition'; Operator = 'eq'; Expected = 0; AbsentIsPass = $true }
    'WNDF-AV-000013' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'LocalSettingOverrideDisableOnAccessProtection'; Operator = 'eq'; Expected = 0; AbsentIsPass = $true }
    'WNDF-AV-000014' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'LocalSettingOverrideRealtimeScanDirection'; Operator = 'eq'; Expected = 0; AbsentIsPass = $true }
    'WNDF-AV-000015' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'LocalSettingOverrideDisableIOAVProtection'; Operator = 'eq'; Expected = 0; AbsentIsPass = $true }
    'WNDF-AV-000016' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'LocalSettingOverrideDisableBehaviorMonitoring'; Operator = 'eq'; Expected = 0; AbsentIsPass = $true }
    'WNDF-AV-000017' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'LocalSettingOverrideDisableRealtimeMonitoring'; Operator = 'eq'; Expected = 0; AbsentIsPass = $true }
    'WNDF-AV-000018' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'RealtimeScanDirection'; Operator = 'eq'; Expected = 0 }
        @{ Applicability = @{ RegistryValueEquals = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'RealtimeScanDirection'; Value = 0 } }; Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'RealtimeScanDirection'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'; Name = 'RealtimeScanDirection'; Operator = 'eq'; Expected = 0 }
        )}
    )}
    # GPO absent is compliant unless Intune applied a non-compliant value.
    'WNDF-AV-000019' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableOnAccessProtection'; Operator = 'eq'; Expected = 0 }
        @{ Applicability = @{ RegistryValueEquals = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableOnAccessProtection'; Value = 0 } }; Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableOnAccessProtection'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'; Name = 'AllowOnAccessProtection'; Operator = 'eq'; Expected = 1; AbsentIsPass = $true }
        )}
    )}
    'WNDF-AV-000020' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableIOAVProtection'; Operator = 'eq'; Expected = 0 }
        @{ Applicability = @{ RegistryValueEquals = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableIOAVProtection'; Value = 0 } }; Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableIOAVProtection'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'; Name = 'AllowIOAVProtection'; Operator = 'eq'; Expected = 1; AbsentIsPass = $true }
        )}
    )}
    # DISA's alternate text calls both 1 compliant and 1 a finding; only 1 passes here.
    'WNDF-AV-000021' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableRealtimeMonitoring'; Operator = 'eq'; Expected = 0 }
        @{ Applicability = @{ RegistryValueEquals = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableRealtimeMonitoring'; Value = 0 } }; Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableRealtimeMonitoring'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'; Name = 'AllowRealtimeMonitoring'; Operator = 'eq'; Expected = 1; AbsentIsPass = $true }
        )}
    )}
    'WNDF-AV-000022' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableBehaviorMonitoring'; Operator = 'eq'; Expected = 0 }
        @{ Applicability = @{ RegistryValueEquals = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableBehaviorMonitoring'; Value = 0 } }; Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableBehaviorMonitoring'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'; Name = 'AllowBehaviorMonitoring'; Operator = 'eq'; Expected = 1; AbsentIsPass = $true }
        )}
    )}
    'WNDF-AV-000023' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableScanOnRealtimeEnable'; Operator = 'eq'; Expected = 0; AbsentIsPass = $true }
    'WNDF-AV-000024' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name = 'DisableArchiveScanning'; Operator = 'eq'; Expected = 0 }
        @{ Applicability = @{ RegistryValueEquals = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name = 'DisableArchiveScanning'; Value = 0 } }; Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name = 'DisableArchiveScanning'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'; Name = 'AllowArchiveScanning'; Operator = 'eq'; Expected = 1; AbsentIsPass = $true }
        )}
    )}
    'WNDF-AV-000025' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name = 'DisableRemovableDriveScanning'; Operator = 'eq'; Expected = 0 }
        @{ Applicability = @{ RegistryValueEquals = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name = 'DisableRemovableDriveScanning'; Value = 0 } }; Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name = 'DisableRemovableDriveScanning'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'; Name = 'AllowFullScanRemovableDriveScanning'; Operator = 'eq'; Expected = 1 }
        )}
    )}
    # 0 (every day) through 7 pass; 8 (never) and absence fail.
    'WNDF-AV-000026' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name = 'ScheduleDay'; Operator = 'in'; Expected = @(0, 1, 2, 3, 4, 5, 6, 7) }
        @{ Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name = 'ScheduleDay'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'; Name = 'ScheduleScanDay'; Operator = 'in'; Expected = @(0, 1, 2, 3, 4, 5, 6, 7) }
        )}
    )}
    'WNDF-AV-000027' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name = 'DisableEmailScanning'; Operator = 'eq'; Expected = 0 }
        @{ Applicability = @{ RegistryValueEquals = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name = 'DisableEmailScanning'; Value = 0 } }; Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name = 'DisableEmailScanning'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'; Name = 'AllowEmailScanning'; Operator = 'eq'; Expected = 1 }
        )}
    )}
    # 1-7 days; 0 disables the check and is a finding.
    'WNDF-AV-000028' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates'; Name = 'ASSignatureDue'; Operator = 'in'; Expected = @(1, 2, 3, 4, 5, 6, 7) }
    'WNDF-AV-000029' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates'; Name = 'AVSignatureDue'; Operator = 'in'; Expected = @(1, 2, 3, 4, 5, 6, 7) }
    'WNDF-AV-000030' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates'; Name = 'ScheduleDay'; Operator = 'eq'; Expected = 0 }
    # Threat-level values are REG_SZ named by severity (5 Severe, 4 High, 2 Medium, 1 Low).
    'WNDF-AV-000031' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'; Name = '5'; Operator = 'in'; Expected = @('2', '3'); Kind = 'string' }
        @{ Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'; Name = '5'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'; Name = 'ThreatSeverityDefaultAction'; Operator = 'in'; Expected = @(1, 2) }
        )}
    )}
    'WNDF-AV-000032' = @{ Applicability = @{ OsBuildAtLeast = 16299 }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'; Operator = 'eq'; Expected = '1'; Kind = 'string' }
    'WNDF-AV-000033' = @{ Applicability = @{ OsBuildAtLeast = 16299 }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'; Operator = 'eq'; Expected = '1'; Kind = 'string' }
    'WNDF-AV-000034' = @{ Applicability = @{ OsBuildAtLeast = 16299 }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = '3B576869-A4EC-4529-8536-B80A7769E899'; Operator = 'eq'; Expected = '1'; Kind = 'string' }
    'WNDF-AV-000035' = @{ Applicability = @{ OsBuildAtLeast = 16299 }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'; Operator = 'eq'; Expected = '1'; Kind = 'string' }
    'WNDF-AV-000036' = @{ Applicability = @{ OsBuildAtLeast = 16299 }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = 'D3E037E1-3EB8-44C8-A917-57927947596D'; Operator = 'eq'; Expected = '1'; Kind = 'string' }
    'WNDF-AV-000037' = @{ Applicability = @{ OsBuildAtLeast = 16299 }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'; Operator = 'eq'; Expected = '1'; Kind = 'string' }
    'WNDF-AV-000038' = @{ Applicability = @{ OsBuildAtLeast = 16299 }; Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'; Operator = 'eq'; Expected = '1'; Kind = 'string' }
    'WNDF-AV-000039' = @{ Applicability = @{ OsBuildAtLeast = 16299 }; Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'; Name = 'EnableNetworkProtection'; Operator = 'eq'; Expected = 1 }
        @{ Applicability = @{ RegistryValueEquals = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'; Name = 'EnableNetworkProtection'; Value = 1 } }; Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'; Name = 'EnableNetworkProtection'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager'; Name = 'EnableNetworkProtection'; Operator = 'eq'; Expected = 1 }
        )}
    )}
    'WNDF-AV-000040' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'; Name = '4'; Operator = 'in'; Expected = @('2', '3'); Kind = 'string' }
    'WNDF-AV-000041' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'; Name = '2'; Operator = 'in'; Expected = @('2', '3'); Kind = 'string' }
    'WNDF-AV-000042' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'; Name = '1'; Operator = 'in'; Expected = @('2', '3'); Kind = 'string' }
    # ASR rule states: '1' block, '2' audit (000047-000049 require audit).
    'WNDF-AV-000043' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'; Operator = 'eq'; Expected = '1'; Kind = 'string' }
    'WNDF-AV-000044' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'; Operator = 'eq'; Expected = '1'; Kind = 'string' }
    'WNDF-AV-000045' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'; Operator = 'eq'; Expected = '1'; Kind = 'string' }
    'WNDF-AV-000046' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = 'c1db55ab-c21a-4637-bb3f-a12568109d35'; Operator = 'eq'; Expected = '1'; Kind = 'string' }
    'WNDF-AV-000047' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'; Operator = 'eq'; Expected = '2'; Kind = 'string' }
    'WNDF-AV-000048' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'; Operator = 'eq'; Expected = '2'; Kind = 'string' }
    'WNDF-AV-000049' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = '01443614-cd74-433a-b99e-2ecdc07bfc25'; Operator = 'eq'; Expected = '2'; Kind = 'string' }
    'WNDF-AV-000050' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = '26190899-1602-49e8-8b27-eb1d0a1ce869'; Operator = 'eq'; Expected = '1'; Kind = 'string' }
    'WNDF-AV-000051' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name = '56a863a9-875e-4185-98a7-b882c64b5ce5'; Operator = 'eq'; Expected = '1'; Kind = 'string' }
    'WNDF-AV-000052' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Name = 'DisableLocalAdminMerge'; Operator = 'eq'; Expected = 1 }
    'WNDF-AV-000055' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Name = 'RandomizeScheduleTaskTimes'; Operator = 'eq'; Expected = 1 }
    'WNDF-AV-000056' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options'; Name = 'UILockdown'; Operator = 'eq'; Expected = 1 }
    'WNDF-AV-000057' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'; Name = 'EnableFileHashComputation'; Operator = 'eq'; Expected = 1 }
    'WNDF-AV-000058' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'; Name = 'MpBafsExtendedTimeout'; Operator = 'eq'; Expected = 50 }
    'WNDF-AV-000064' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'DisableScriptScanning'; Operator = 'eq'; Expected = 0 }
    'WNDF-AV-000065' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name = 'OobeEnableRtpAndSigUpdate'; Operator = 'eq'; Expected = 1 }
    # NA on desktops, and woscap has no server/workstation fact.
    'WNDF-AV-000068' = @{ Type = 'Manual'
        Question = 'Is this system a Windows Server? If not, mark NA. If it is, is HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\AllowNetworkProtectionOnWinServer = 1 (REG_DWORD)? Any other value or absence is a finding.'
        Evidence = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'; Name = 'AllowNetworkProtectionOnWinServer' } }
    'WNDF-AV-000070' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features'; Name = 'PassiveRemediation'; Operator = 'eq'; Expected = 1 }
    'WNDF-AV-000071' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'; Name = 'EnableDynamicSignatureDroppedEventReporting'; Operator = 'eq'; Expected = 1 }
    'WNDF-AV-000072' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name = 'QuickScanIncludeExclusions'; Operator = 'eq'; Expected = 1 }
    'WNDF-AV-000073' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'; Name = 'MpCloudBlockLevel'; Operator = 'eq'; Expected = 2 }
    'WNDF-AV-000074' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS'; Name = 'EnableConvertWarnToBlock'; Operator = 'eq'; Expected = 1 }
    'WNDF-AV-000075' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS'; Name = 'AllowSwitchToAsyncInspection'; Operator = 'eq'; Expected = 1 }
    'WNDF-AV-000076' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name = 'DisablePackedExeScanning'; Operator = 'eq'; Expected = 0 }
    'WNDF-AV-000077' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name = 'DisableHeuristics'; Operator = 'eq'; Expected = 0 }
    'WNDF-AV-000100' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'; Name = 'HideExclusionsFromLocalAdmins'; Operator = 'eq'; Expected = 1 }
}

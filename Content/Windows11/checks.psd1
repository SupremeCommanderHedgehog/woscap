# Windows 11 STIG V2R8 content pack. Every descriptor is derived from the rule's
# DISA check-content and adversarially re-derived against it after authoring: a
# wrong path or SID list produces a silent false Pass, the worst outcome this
# tool has. A rule whose check-content cannot be expressed faithfully is authored
# as Type='Manual' rather than approximated.
#
# UserRight rules use 'subsetof', not 'setequals'. The STIG wording is "if any
# groups or accounts OTHER THAN the following", which a host satisfies by
# granting the right to fewer principals than listed; setequals wrongly failed
# those. Deny-rights rules use 'supersetof' - those say the listed principals
# MUST be defined.
@{
    'WN11-00-000032' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\FVE'; Name='MinimumPIN'; Operator='ge'; Expected=6 }
    'WN11-00-000126' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount'; Name='DisableUserAuth'; Operator='eq'; Expected=1 }
    'WN11-00-000150' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'; Name='DisableExceptionChainValidation'; Operator='eq'; Expected=0 }
    'WN11-00-000165' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='SMB1'; Operator='eq'; Expected=0 }
    'WN11-00-000170' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'; Name='Start'; Operator='eq'; Expected=4 }
    'WN11-00-000210' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Connectivity'; Name='AllowBluetooth'; Operator='eq'; Expected=0 }
    'WN11-AU-000005' = @{ Type='AuditPolicy'; Subcategory='Credential Validation'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000010' = @{ Type='AuditPolicy'; Subcategory='Credential Validation'; Operator='includes'; Expected='Success' }
    'WN11-AU-000030' = @{ Type='AuditPolicy'; Subcategory='Security Group Management'; Operator='includes'; Expected='Success' }
    'WN11-AU-000035' = @{ Type='AuditPolicy'; Subcategory='User Account Management'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000040' = @{ Type='AuditPolicy'; Subcategory='User Account Management'; Operator='includes'; Expected='Success' }
    'WN11-AU-000045' = @{ Type='AuditPolicy'; Subcategory='Plug and Play Events'; Operator='includes'; Expected='Success' }
    'WN11-AU-000050' = @{ Type='AuditPolicy'; Subcategory='Process Creation'; Operator='includes'; Expected='Success' }
    'WN11-AU-000054' = @{ Type='AuditPolicy'; Subcategory='Account Lockout'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000060' = @{ Type='AuditPolicy'; Subcategory='Group Membership'; Operator='includes'; Expected='Success' }
    'WN11-AU-000065' = @{ Type='AuditPolicy'; Subcategory='Logoff'; Operator='includes'; Expected='Success' }
    'WN11-AU-000070' = @{ Type='AuditPolicy'; Subcategory='Logon'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000075' = @{ Type='AuditPolicy'; Subcategory='Logon'; Operator='includes'; Expected='Success' }
    'WN11-AU-000080' = @{ Type='AuditPolicy'; Subcategory='Special Logon'; Operator='includes'; Expected='Success' }
    'WN11-AU-000081' = @{ Type='AuditPolicy'; Subcategory='File Share'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000082' = @{ Type='AuditPolicy'; Subcategory='File Share'; Operator='includes'; Expected='Success' }
    'WN11-AU-000083' = @{ Type='AuditPolicy'; Subcategory='Other Object Access Events'; Operator='includes'; Expected='Success' }
    'WN11-AU-000084' = @{ Type='AuditPolicy'; Subcategory='Other Object Access Events'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000085' = @{ Type='AuditPolicy'; Subcategory='Removable Storage'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000090' = @{ Type='AuditPolicy'; Subcategory='Removable Storage'; Operator='includes'; Expected='Success' }
    'WN11-AU-000100' = @{ Type='AuditPolicy'; Subcategory='Audit Policy Change'; Operator='includes'; Expected='Success' }
    'WN11-AU-000105' = @{ Type='AuditPolicy'; Subcategory='Authentication Policy Change'; Operator='includes'; Expected='Success' }
    'WN11-AU-000107' = @{ Type='AuditPolicy'; Subcategory='Authorization Policy Change'; Operator='includes'; Expected='Success' }
    'WN11-AU-000110' = @{ Type='AuditPolicy'; Subcategory='Sensitive Privilege Use'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000115' = @{ Type='AuditPolicy'; Subcategory='Sensitive Privilege Use'; Operator='includes'; Expected='Success' }
    'WN11-AU-000120' = @{ Type='AuditPolicy'; Subcategory='IPsec Driver'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000130' = @{ Type='AuditPolicy'; Subcategory='Other System Events'; Operator='includes'; Expected='Success' }
    'WN11-AU-000135' = @{ Type='AuditPolicy'; Subcategory='Other System Events'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000140' = @{ Type='AuditPolicy'; Subcategory='Security State Change'; Operator='includes'; Expected='Success' }
    'WN11-AU-000150' = @{ Type='AuditPolicy'; Subcategory='Security System Extension'; Operator='includes'; Expected='Success' }
    'WN11-AU-000155' = @{ Type='AuditPolicy'; Subcategory='System Integrity'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000160' = @{ Type='AuditPolicy'; Subcategory='System Integrity'; Operator='includes'; Expected='Success' }
    'WN11-AU-000500' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; Name='MaxSize'; Operator='ge'; Expected=32768 }
    'WN11-AU-000505' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name='MaxSize'; Operator='ge'; Expected=5120000 }
    'WN11-AU-000510' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; Name='MaxSize'; Operator='ge'; Expected=32768 }
    'WN11-AU-000555' = @{ Type='AuditPolicy'; Subcategory='Other Policy Change Events'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000560' = @{ Type='AuditPolicy'; Subcategory='Other Logon/Logoff Events'; Operator='includes'; Expected='Success' }
    'WN11-AU-000565' = @{ Type='AuditPolicy'; Subcategory='Other Logon/Logoff Events'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000570' = @{ Type='AuditPolicy'; Subcategory='Detailed File Share'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000575' = @{ Type='AuditPolicy'; Subcategory='MPSSVC Rule-Level Policy Change'; Operator='includes'; Expected='Success' }
    'WN11-AU-000580' = @{ Type='AuditPolicy'; Subcategory='MPSSVC Rule-Level Policy Change'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000583' = @{ Type='AuditPolicy'; Subcategory='Handle Manipulation'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000585' = @{ Type='AuditPolicy'; Subcategory='Process Creation'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000586' = @{ Type='AuditPolicy'; Subcategory='Registry'; Operator='includes'; Expected='Success' }
    'WN11-AU-000587' = @{ Type='AuditPolicy'; Subcategory='Sensitive Privilege Use'; Operator='includes'; Expected='Success' }
    'WN11-AU-000588' = @{ Type='AuditPolicy'; Subcategory='Sensitive Privilege Use'; Operator='includes'; Expected='Failure' }
    'WN11-AU-000589' = @{ Type='AuditPolicy'; Subcategory='Registry'; Operator='includes'; Expected='Failure' }
    'WN11-CC-000005' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name='NoLockScreenCamera'; Operator='eq'; Expected=1 }
    'WN11-CC-000010' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name='NoLockScreenSlideshow'; Operator='eq'; Expected=1 }
    'WN11-CC-000020' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; Name='DisableIpSourceRouting'; Operator='eq'; Expected=2 }
    'WN11-CC-000025' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='DisableIPSourceRouting'; Operator='eq'; Expected=2 }
    'WN11-CC-000030' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='EnableICMPRedirect'; Operator='eq'; Expected=0 }
    'WN11-CC-000035' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'; Name='NoNameReleaseOnDemand'; Operator='eq'; Expected=1 }
    'WN11-CC-000037' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='LocalAccountTokenFilterPolicy'; Operator='eq'; Expected=0 }
    'WN11-CC-000038' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'; Name='UseLogonCredential'; Operator='eq'; Expected=0 }
    'WN11-CC-000040' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; Name='AllowInsecureGuestAuth'; Operator='eq'; Expected=0 }
    'WN11-CC-000044' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections'; Name='NC_ShowSharedAccessUI'; Operator='eq'; Expected=0 }
    'WN11-CC-000060' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'; Name='fBlockNonDomain'; Operator='eq'; Expected=1 }
    'WN11-CC-000066' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name='ProcessCreationIncludeCmdLine_Enabled'; Operator='eq'; Expected=1 }
    'WN11-CC-000068' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'; Name='AllowProtectedCreds'; Operator='eq'; Expected=1 }
    'WN11-CC-000090' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'; Name='NoGPOListChanges'; Operator='eq'; Expected=0 }
    'WN11-CC-000100' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name='DisableWebPnPDownload'; Operator='eq'; Expected=1 }
    'WN11-CC-000105' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoWebServices'; Operator='eq'; Expected=1 }
    'WN11-CC-000110' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name='DisableHTTPPrinting'; Operator='eq'; Expected=1 }
    'WN11-CC-000115' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name='DevicePKInitEnabled'; Operator='eq'; Expected=1 }
    'WN11-CC-000120' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='DontDisplayNetworkSelectionUI'; Operator='eq'; Expected=1 }
    'WN11-CC-000130' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnumerateLocalUsers'; Operator='eq'; Expected=0 }
    'WN11-CC-000145' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'; Name='DCSettingIndex'; Operator='eq'; Expected=1 }
    'WN11-CC-000150' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'; Name='ACSettingIndex'; Operator='eq'; Expected=1 }
    'WN11-CC-000155' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fAllowToGetHelp'; Operator='eq'; Expected=0 }
    'WN11-CC-000165' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'; Name='RestrictRemoteClients'; Operator='eq'; Expected=1 }
    'WN11-CC-000170' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='MSAOptional'; Operator='eq'; Expected=1 }
    'WN11-CC-000175' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'; Name='DisableInventory'; Operator='eq'; Expected=1 }
    'WN11-CC-000180' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoAutoplayfornonVolume'; Operator='eq'; Expected=1 }
    'WN11-CC-000185' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoAutorun'; Operator='eq'; Expected=1 }
    'WN11-CC-000190' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer'; Name='NoDriveTypeAutoRun'; Operator='eq'; Expected=255 }
    'WN11-CC-000200' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'; Name='EnumerateAdministrators'; Operator='eq'; Expected=0 }
    'WN11-CC-000204' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='LimitEnhancedDiagnosticDataWindowsAnalytics'; Operator='eq'; Expected=1 }
    'WN11-CC-000215' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoDataExecutionPrevention'; Operator='eq'; Expected=0 }
    'WN11-CC-000220' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoHeapTerminationOnCorruption'; Operator='eq'; Expected=0 }
    'WN11-CC-000225' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='PreXPSP2ShellProtocolBehavior'; Operator='eq'; Expected=0 }
    'WN11-CC-000252' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'; Name='AllowGameDVR'; Operator='eq'; Expected=0 }
    'WN11-CC-000255' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork'; Name='RequireSecurityDevice'; Operator='eq'; Expected=1 }
    'WN11-CC-000260' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'; Name='MinimumPINLength'; Operator='ge'; Expected=6 }
    'WN11-CC-000270' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='DisablePasswordSaving'; Operator='eq'; Expected=1 }
    'WN11-CC-000275' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDisableCdm'; Operator='eq'; Expected=1 }
    'WN11-CC-000280' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fPromptForPassword'; Operator='eq'; Expected=1 }
    'WN11-CC-000285' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fEncryptRPCTraffic'; Operator='eq'; Expected=1 }
    'WN11-CC-000290' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='MinEncryptionLevel'; Operator='eq'; Expected=3 }
    'WN11-CC-000295' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'; Name='DisableEnclosureDownload'; Operator='eq'; Expected=1 }
    'WN11-CC-000300' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'; Name='AllowBasicAuthInClear'; Operator='eq'; Expected=0 }
    'WN11-CC-000305' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='AllowIndexingEncryptedStoresOrItems'; Operator='eq'; Expected=0 }
    'WN11-CC-000310' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='EnableUserControl'; Operator='eq'; Expected=0 }
    'WN11-CC-000315' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='AlwaysInstallElevated'; Operator='eq'; Expected=0 }
    'WN11-CC-000325' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='DisableAutomaticRestartSignOn'; Operator='eq'; Expected=1 }
    'WN11-CC-000326' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name='EnableScriptBlockLogging'; Operator='eq'; Expected=1 }
    'WN11-CC-000327' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name='EnableTranscripting'; Operator='eq'; Expected=1 }
    'WN11-CC-000330' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowBasic'; Operator='eq'; Expected=0 }
    'WN11-CC-000335' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowUnencryptedTraffic'; Operator='eq'; Expected=0 }
    'WN11-CC-000345' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='AllowBasic'; Operator='eq'; Expected=0 }
    'WN11-CC-000350' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='AllowUnencryptedTraffic'; Operator='eq'; Expected=0 }
    'WN11-CC-000355' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='DisableRunAs'; Operator='eq'; Expected=1 }
    'WN11-CC-000360' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowDigest'; Operator='eq'; Expected=0 }
    'WN11-CC-000370' = @{ Type='Registry'; Path='HKLM:\Software\Policies\Microsoft\Windows\System'; Name='AllowDomainPINLogon'; Operator='eq'; Expected=0 }
    'WN11-CC-000390' = @{ Type='Registry'; Path='HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name='DisableThirdPartySuggestions'; Operator='eq'; Expected=1 }
    'WN11-EP-000310' = @{ Type='Registry'; Path='HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection'; Name='DeviceEnumerationPolicy'; Operator='eq'; Expected=0 }
    'WN11-SO-000015' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LimitBlankPasswordUse'; Operator='eq'; Expected=1 }
    'WN11-SO-000030' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='SCENoApplyLegacyAuditPolicy'; Operator='eq'; Expected=1 }
    'WN11-SO-000035' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='RequireSignOrSeal'; Operator='eq'; Expected=1 }
    'WN11-SO-000040' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='SealSecureChannel'; Operator='eq'; Expected=1 }
    'WN11-SO-000045' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='SignSecureChannel'; Operator='eq'; Expected=1 }
    'WN11-SO-000050' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='DisablePasswordChange'; Operator='eq'; Expected=0 }
    'WN11-SO-000060' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='RequireStrongKey'; Operator='eq'; Expected=1 }
    'WN11-SO-000100' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='RequireSecuritySignature'; Operator='eq'; Expected=1 }
    'WN11-SO-000110' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='EnablePlainTextPassword'; Operator='eq'; Expected=0 }
    'WN11-SO-000120' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='RequireSecuritySignature'; Operator='eq'; Expected=1 }
    'WN11-SO-000145' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymousSAM'; Operator='eq'; Expected=1 }
    'WN11-SO-000150' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymous'; Operator='eq'; Expected=1 }
    'WN11-SO-000160' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='EveryoneIncludesAnonymous'; Operator='eq'; Expected=0 }
    'WN11-SO-000165' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='RestrictNullSessAccess'; Operator='eq'; Expected=1 }
    'WN11-SO-000167' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictRemoteSAM'; Operator='eq'; Expected='O:BAG:BAD:(A;;RC;;;BA)' }
    'WN11-SO-000180' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0'; Name='allownullsessionfallback'; Operator='eq'; Expected=0 }
    'WN11-SO-000185' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u'; Name='AllowOnlineID'; Operator='eq'; Expected=0 }
    'WN11-SO-000190' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name='SupportedEncryptionTypes'; Operator='eq'; Expected=2147483640 }
    'WN11-SO-000195' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='NoLMHash'; Operator='eq'; Expected=1 }
    'WN11-SO-000205' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LmCompatibilityLevel'; Operator='eq'; Expected=5 }
    'WN11-SO-000210' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'; Name='LDAPClientIntegrity'; Operator='eq'; Expected=1 }
    'WN11-SO-000215' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='NTLMMinClientSec'; Operator='eq'; Expected=537395200 }
    'WN11-SO-000220' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='NTLMMinServerSec'; Operator='eq'; Expected=537395200 }
    'WN11-SO-000240' = @{ Type='Registry'; Path='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'; Name='ProtectionMode'; Operator='eq'; Expected=1 }
    'WN11-SO-000245' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='FilterAdministratorToken'; Operator='eq'; Expected=1 }
    'WN11-SO-000250' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorAdmin'; Operator='eq'; Expected=2 }
    'WN11-SO-000255' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorUser'; Operator='eq'; Expected=0 }
    'WN11-SO-000260' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableInstallerDetection'; Operator='eq'; Expected=1 }
    'WN11-SO-000265' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableSecureUIAPaths'; Operator='eq'; Expected=1 }
    'WN11-SO-000270' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableLUA'; Operator='eq'; Expected=1 }
    'WN11-SO-000275' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableVirtualization'; Operator='eq'; Expected=1 }
    'WN11-UC-000015' = @{ Type='Registry'; Path='HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'; Name='NoToastApplicationNotificationOnLockScreen'; Operator='eq'; Expected=1 }
    # --- User Rights Assignment (Se* privileges; exact set match) ---
    'WN11-UR-000005' = @{ Type = 'UserRight'; Privilege = 'SeTrustedCredManAccessPrivilege'; Operator = 'subsetof' ; Expected = @() }
    'WN11-UR-000015' = @{ Type = 'UserRight'; Privilege = 'SeTcbPrivilege';                   Operator = 'subsetof' ; Expected = @() }
    'WN11-UR-000025' = @{ Type = 'UserRight'; Privilege = 'SeInteractiveLogonRight';          Operator = 'subsetof' ; Expected = @('Administrators','Users') }
    'WN11-UR-000030' = @{ Type = 'UserRight'; Privilege = 'SeBackupPrivilege';                Operator = 'subsetof' ; Expected = @('Administrators') }
    'WN11-UR-000035' = @{ Type = 'UserRight'; Privilege = 'SeSystemtimePrivilege';            Operator = 'subsetof' ; Expected = @('Administrators','LOCAL SERVICE') }
    'WN11-UR-000040' = @{ Type = 'UserRight'; Privilege = 'SeCreatePagefilePrivilege';        Operator = 'subsetof' ; Expected = @('Administrators') }
    'WN11-UR-000045' = @{ Type = 'UserRight'; Privilege = 'SeCreateTokenPrivilege';           Operator = 'subsetof' ; Expected = @() }
    'WN11-UR-000050' = @{ Type = 'UserRight'; Privilege = 'SeCreateGlobalPrivilege';          Operator = 'subsetof' ; Expected = @('Administrators','LOCAL SERVICE','NETWORK SERVICE','SERVICE') }
    'WN11-UR-000055' = @{ Type = 'UserRight'; Privilege = 'SeCreatePermanentPrivilege';       Operator = 'subsetof' ; Expected = @() }
    'WN11-UR-000065' = @{ Type = 'UserRight'; Privilege = 'SeDebugPrivilege';                 Operator = 'subsetof' ; Expected = @('Administrators') }
    'WN11-UR-000095' = @{ Type = 'UserRight'; Privilege = 'SeEnableDelegationPrivilege';      Operator = 'subsetof' ; Expected = @() }
    'WN11-UR-000100' = @{ Type = 'UserRight'; Privilege = 'SeRemoteShutdownPrivilege';        Operator = 'subsetof' ; Expected = @('Administrators') }
    'WN11-UR-000120' = @{ Type = 'UserRight'; Privilege = 'SeLoadDriverPrivilege';            Operator = 'subsetof' ; Expected = @('Administrators') }
    'WN11-UR-000125' = @{ Type = 'UserRight'; Privilege = 'SeLockMemoryPrivilege';            Operator = 'subsetof' ; Expected = @() }
    'WN11-UR-000140' = @{ Type = 'UserRight'; Privilege = 'SeSystemEnvironmentPrivilege';     Operator = 'subsetof' ; Expected = @('Administrators') }
    'WN11-UR-000145' = @{ Type = 'UserRight'; Privilege = 'SeManageVolumePrivilege';          Operator = 'subsetof' ; Expected = @('Administrators') }
    'WN11-UR-000150' = @{ Type = 'UserRight'; Privilege = 'SeProfileSingleProcessPrivilege';  Operator = 'subsetof' ; Expected = @('Administrators') }
    'WN11-UR-000160' = @{ Type = 'UserRight'; Privilege = 'SeRestorePrivilege';               Operator = 'subsetof' ; Expected = @('Administrators') }
    'WN11-UR-000165' = @{ Type = 'UserRight'; Privilege = 'SeTakeOwnershipPrivilege';         Operator = 'subsetof' ; Expected = @('Administrators') }
    # --- Service ---
    'WN11-00-000175' = @{ Type = 'Service'; Name = 'seclogon'; Operator = 'eq'; Expected = 'Disabled' }

    # ------------------------------------------------------------------
    # Coverage completion (#70). Sorted by STIG ID within each family.
    # ------------------------------------------------------------------

    # --- WN11-AC-*: account policy (secedit, System Access) ---
    # 0 means "administrator must unlock", which the STIG calls more restrictive
    # and explicitly not a finding, so it is accepted alongside >= 15.
    'WN11-AC-000005' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'SecEdit'; Name = 'LockoutDuration'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'SecEdit'; Name = 'LockoutDuration'; Operator = 'ge'; Expected = 15 }
    )}
    # "0 or more than 3 attempts" is a finding, so both bounds must hold.
    'WN11-AC-000010' = @{ Type = 'All'; Checks = @(
        @{ Type = 'SecEdit'; Name = 'LockoutBadCount'; Operator = 'ne'; Expected = 0 }
        @{ Type = 'SecEdit'; Name = 'LockoutBadCount'; Operator = 'le'; Expected = 3 }
    )}
    'WN11-AC-000015' = @{ Type = 'SecEdit'; Name = 'ResetLockoutCount';     Operator = 'ge'; Expected = 15 }
    'WN11-AC-000020' = @{ Type = 'SecEdit'; Name = 'PasswordHistorySize';   Operator = 'ge'; Expected = 24 }
    # 0 (never expires) is a finding as well as > 60.
    'WN11-AC-000025' = @{ Type = 'All'; Checks = @(
        @{ Type = 'SecEdit'; Name = 'MaximumPasswordAge'; Operator = 'ne'; Expected = 0 }
        @{ Type = 'SecEdit'; Name = 'MaximumPasswordAge'; Operator = 'le'; Expected = 60 }
    )}
    'WN11-AC-000030' = @{ Type = 'SecEdit'; Name = 'MinimumPasswordAge';    Operator = 'ge'; Expected = 1 }
    'WN11-AC-000035' = @{ Type = 'SecEdit'; Name = 'MinimumPasswordLength'; Operator = 'ge'; Expected = 14 }
    'WN11-AC-000040' = @{ Type = 'SecEdit'; Name = 'PasswordComplexity';    Operator = 'eq'; Expected = 1 }
    'WN11-AC-000045' = @{ Type = 'SecEdit'; Name = 'ClearTextPassword';     Operator = 'eq'; Expected = 0 }

    # --- WN11-AU-000515/520/525: event log ACLs ---
    # ALL APPLICATION PACKAGES holding Special Permissions is explicitly not a
    # finding, so it is an allowed principal.
    'WN11-AU-000515' = @{ Type = 'Acl'
        Path = @('%SystemRoot%\System32\winevt\Logs\Application.evtx')
        AllowedPrincipals = @('NT SERVICE\EventLog','NT AUTHORITY\SYSTEM','BUILTIN\Administrators','APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES') }
    'WN11-AU-000520' = @{ Type = 'Acl'
        Path = @('%SystemRoot%\System32\winevt\Logs\Security.evtx')
        AllowedPrincipals = @('NT SERVICE\EventLog','NT AUTHORITY\SYSTEM','BUILTIN\Administrators','APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES') }
    'WN11-AU-000525' = @{ Type = 'Acl'
        Path = @('%SystemRoot%\System32\winevt\Logs\System.evtx')
        AllowedPrincipals = @('NT SERVICE\EventLog','NT AUTHORITY\SYSTEM','BUILTIN\Administrators','APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES') }

    # --- WN11-CC-*: computer configuration ---
    # Whether the camera is physically covered cannot be read; the registry
    # fallback the STIG names can be. NA when the host has no camera.
    'WN11-CC-000007' = @{ Applicability = @{ CameraPresent = $true }
        Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'
        Name = 'Value'; Operator = 'eq'; Expected = 'Deny' }
    # The same value under four Classes hives; all four must be set.
    'WN11-CC-000039' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Classes\batfile\shell\runasuser'; Name = 'SuppressionPolicy'; Operator = 'eq'; Expected = 4096 }
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser'; Name = 'SuppressionPolicy'; Operator = 'eq'; Expected = 4096 }
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser'; Name = 'SuppressionPolicy'; Operator = 'eq'; Expected = 4096 }
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser'; Name = 'SuppressionPolicy'; Operator = 'eq'; Expected = 4096 }
    )}
    'WN11-CC-000050' = @{ Applicability = @{ DomainJoined = $true }
        Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
           Name = '\\*\NETLOGON'; Operator = 'regex'; Expected = 'RequireMutualAuthentication=1[\s\S]*RequireIntegrity=1' }
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
           Name = '\\*\SYSVOL';  Operator = 'regex'; Expected = 'RequireMutualAuthentication=1[\s\S]*RequireIntegrity=1' }
    )}
    # REG_MULTI_SZ where the order is the policy, hence 'sequence'.
    'WN11-CC-000052' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
        Name = 'EccCurves'; Operator = 'sequence'; Expected = @('NistP384','NistP256') }
    # Default is Enabled; only an explicit 0 is a finding.
    'WN11-CC-000055' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
        Name = 'fMinimizeConnections'; Operator = 'ne'; Expected = 0; AbsentIsPass = $true }
    'WN11-CC-000070' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Cim'; Namespace = 'root\Microsoft\Windows\DeviceGuard'; ClassName = 'Win32_DeviceGuard'
           Property = 'RequiredSecurityProperties'; Operator = 'includes'; Expected = 2 }
        @{ Type = 'Cim'; Namespace = 'root\Microsoft\Windows\DeviceGuard'; ClassName = 'Win32_DeviceGuard'
           Property = 'VirtualizationBasedSecurityStatus'; Operator = 'eq'; Expected = 2 }
    )}
    'WN11-CC-000075' = @{ Type = 'Cim'; Namespace = 'root\Microsoft\Windows\DeviceGuard'; ClassName = 'Win32_DeviceGuard'
        Property = 'SecurityServicesRunning'; Operator = 'includes'; Expected = 1 }
    'WN11-CC-000080' = @{ Type = 'Cim'; Namespace = 'root\Microsoft\Windows\DeviceGuard'; ClassName = 'Win32_DeviceGuard'
        Property = 'SecurityServicesRunning'; Operator = 'includes'; Expected = 2 }
    # 7 ("All", including bad) is the finding; the value must exist.
    'WN11-CC-000085' = @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
        Name = 'DriverLoadPolicy'; Operator = 'in'; Expected = @(1,3,8) }
    # GPO path or Intune path, and the two GPO value names the STIG lists.
    'WN11-CC-000195' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'; Name = 'EnhancedAntiSpoofing'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'; Name = 'FacialFeaturesUseEnhancedAntiSpoofing'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics'; Name = 'EnhancedAntiSpoofing'; Operator = 'eq'; Expected = 1 }
    )}
    'WN11-CC-000205' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        Name = 'AllowTelemetry'; Operator = 'in'; Expected = @(0,1) }
    # Policy path or the standalone Settings path; 3 (Internet) is the finding.
    'WN11-CC-000206' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; Name = 'DODownloadMode'; Operator = 'in'; Expected = @(0,1,2,99,100) }
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config'; Name = 'DODownloadMode'; Operator = 'in'; Expected = @(0,1) }
    )}
    'WN11-CC-000210' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'EnableSmartScreen';     Operator = 'eq'; Expected = 1 }
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'ShellSmartScreenLevel'; Operator = 'eq'; Expected = 'Block' }
    )}
    'WN11-CC-000320' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'
        Name = 'SafeForScripting'; Operator = 'ne'; Expected = 1; AbsentIsPass = $true }
    # NA when voice activation is disallowed for all users.
    'WN11-CC-000365' = @{ Applicability = @{ RegistryValueEquals = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; Name = 'LetAppsActivateWithVoice'; Value = 2 } }
        Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
        Name = 'LetAppsActivateWithVoiceAboveLock'; Operator = 'eq'; Expected = 2 }
    'WN11-CC-000385' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'; Name = 'AllowWindowsInkWorkspace'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\WindowsInkWorkspace'; Name = 'AllowWindowsInkWorkspace'; Operator = 'eq'; Expected = 1 }
    )}
    'WN11-CC-000391' = @{ Type = 'OptionalFeature'; FeatureName = 'Internet-Explorer-Optional-*'; Operator = 'notin'; Expected = @('Enabled') }

    # --- WN11-PK-*: certificates ---
    # PK-000005/000010 require CURRENT roots, so RequireUnexpired is on.
    'WN11-PK-000005' = @{ Type = 'Certificate'; Store = 'root'; RequireUnexpired = $true
        Match = @{ Subject = 'CN=DoD Root CA' }; Operator = 'ge'; Expected = 1 }
    'WN11-PK-000010' = @{ Type = 'Certificate'; Store = 'root'; RequireUnexpired = $true
        Match = @{ Subject = 'CN=ECA Root CA' }; Operator = 'ge'; Expected = 1 }
    # PK-000015/000020 name cross-certificates that must be PRESENT in the
    # untrusted store even though their NotAfter has passed, so no unexpired
    # requirement here - that is the point of the disallowed store.
    'WN11-PK-000015' = @{ Type = 'Certificate'; Store = 'disallowed'
        Match = @{ Issuer = 'CN=DoD Interoperability Root CA'; Subject = 'CN=DoD Root CA' }
        Operator = 'ge'; Expected = 1 }
    'WN11-PK-000020' = @{ Type = 'Certificate'; Store = 'disallowed'
        Match = @{ Issuer = 'CCEB Interoperability Root CA' }
        Operator = 'ge'; Expected = 1 }

    # --- WN11-RG-000005: HKLM hive ACLs ---
    # Non-privileged groups must not hold more than Read. The app-container SID
    # below is the one Microsoft grants Read and the STIG says is not a finding.
    'WN11-RG-000005' = @{ Type = 'Acl'
        Path = @('HKLM:\SECURITY','HKLM:\SOFTWARE','HKLM:\SYSTEM')
        AllowedPrincipals = @('NT AUTHORITY\SYSTEM','BUILTIN\Administrators','CREATOR OWNER','APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES','S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681')
        MaxRights = @('ReadKey','QueryValues','EnumerateSubKeys','Notify','ReadPermissions','Read') }

    # --- WN11-SO-*: security options ---
    'WN11-SO-000010' = @{ Type = 'SecEdit'; Name = 'EnableGuestAccount';    Operator = 'eq'; Expected = 0 }
    # secedit renders these REG_SZ values quoted, so the expected form is quoted.
    'WN11-SO-000020' = @{ Type = 'SecEdit'; Name = 'NewAdministratorName'; Operator = 'ne'; Expected = '"Administrator"' }
    'WN11-SO-000025' = @{ Type = 'SecEdit'; Name = 'NewGuestName';         Operator = 'ne'; Expected = '"Guest"' }
    'WN11-SO-000055' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'MaximumPasswordAge'; Operator = 'ne'; Expected = 0 }
        @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'MaximumPasswordAge'; Operator = 'le'; Expected = 30 }
    )}
    'WN11-SO-000070' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'InactivityTimeoutSecs'; Operator = 'ne'; Expected = 0 }
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'InactivityTimeoutSecs'; Operator = 'le'; Expected = 900 }
    )}
    # The banner is stored with deployment-dependent line breaks, so this asserts
    # the opening clause rather than byte equality. A site-defined equivalent is
    # a legitimate deviation and belongs in an exception profile.
    'WN11-SO-000075' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'LegalNoticeText'; Operator = 'regex'
        Expected = 'You are accessing a U\.S\. Government \(USG\) Information System \(IS\) that is provided for USG-authorized use only' }
    # A site-defined title is permitted, so this only requires a non-empty one.
    'WN11-SO-000080' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        Name = 'LegalNoticeCaption'; Operator = 'regex'; Expected = '\S' }
    # REG_SZ holding a number; 'le' compares numerically.
    'WN11-SO-000085' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Name = 'CachedLogonsCount'; Operator = 'le'; Expected = 10 }
    'WN11-SO-000095' = @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Name = 'SCRemoveOption'; Operator = 'in'; Expected = @('1','2') }
    'WN11-SO-000140' = @{ Type = 'SecEdit'; Name = 'LSAAnonymousNameLookup'; Operator = 'eq'; Expected = 0 }
    'WN11-SO-000230' = @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy'
        Name = 'Enabled'; Operator = 'eq'; Expected = 1 }
    'WN11-SO-000251' = @{ Applicability = @{ DomainJoined = $true }
        Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Cryptography\Calais\Readers';    Name = '(default)'; Operator = 'exists'; Expected = $true }
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards'; Name = '(default)'; Operator = 'exists'; Expected = $true }
    )}

    # --- WN11-UC-000020 ---
    # HKCU reads the SCANNING account's hive, not the audited user's. Recorded
    # as a known limitation in MANUAL.md; CC-000390 carries the same caveat.
    'WN11-UC-000020' = @{ Type = 'Registry'; Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
        Name = 'SaveZoneInformation'; Operator = 'ne'; Expected = 1; AbsentIsPass = $true }

    # --- WN11-UR-*: user rights ---
    # "only assigned to" -> subsetof. Deny rights say the listed principals MUST
    # be defined -> supersetof, with the domain-only additions gated so a
    # standalone host evaluates only the always-applicable branch.
    'WN11-UR-000010' = @{ Type = 'UserRight'; Privilege = 'SeNetworkLogonRight'
        Operator = 'subsetof'; Expected = @('Administrators','Remote Desktop Users') }
    'WN11-UR-000060' = @{ Type = 'UserRight'; Privilege = 'SeCreateSymbolicLinkPrivilege'
        Operator = 'subsetof'; Expected = @('Administrators','NT VIRTUAL MACHINE\Virtual Machines') }
    'WN11-UR-000070' = @{ Type = 'All'; Checks = @(
        @{ Type = 'UserRight'; Privilege = 'SeDenyNetworkLogonRight'; Operator = 'supersetof'; Expected = @('Guests') }
        @{ Applicability = @{ DomainJoined = $true }
           Type = 'UserRight'; Privilege = 'SeDenyNetworkLogonRight'; Operator = 'supersetof'
           Expected = @('Enterprise Admins','Domain Admins','Local account') }
    )}
    'WN11-UR-000075' = @{ Applicability = @{ DomainJoined = $true }
        Type = 'UserRight'; Privilege = 'SeDenyBatchLogonRight'
        Operator = 'supersetof'; Expected = @('Enterprise Admins','Domain Admins') }
    'WN11-UR-000080' = @{ Applicability = @{ DomainJoined = $true }
        Type = 'UserRight'; Privilege = 'SeDenyServiceLogonRight'
        Operator = 'supersetof'; Expected = @('Enterprise Admins','Domain Admins') }
    'WN11-UR-000085' = @{ Type = 'All'; Checks = @(
        @{ Type = 'UserRight'; Privilege = 'SeDenyInteractiveLogonRight'; Operator = 'supersetof'; Expected = @('Guests') }
        @{ Applicability = @{ DomainJoined = $true }
           Type = 'UserRight'; Privilege = 'SeDenyInteractiveLogonRight'; Operator = 'supersetof'
           Expected = @('Enterprise Admins','Domain Admins') }
    )}
    'WN11-UR-000090' = @{ Type = 'All'; Checks = @(
        @{ Type = 'UserRight'; Privilege = 'SeDenyRemoteInteractiveLogonRight'; Operator = 'supersetof'; Expected = @('Guests') }
        @{ Applicability = @{ DomainJoined = $true }
           Type = 'UserRight'; Privilege = 'SeDenyRemoteInteractiveLogonRight'; Operator = 'supersetof'
           Expected = @('Enterprise Admins','Domain Admins','Local account') }
    )}
    'WN11-UR-000110' = @{ Type = 'UserRight'; Privilege = 'SeImpersonatePrivilege'
        Operator = 'subsetof'; Expected = @('Administrators','LOCAL SERVICE','NETWORK SERVICE','SERVICE') }
    # An organizational "Auditors" group is explicitly not a finding; that
    # allowance is site-specific and belongs in an exception profile.
    'WN11-UR-000130' = @{ Type = 'UserRight'; Privilege = 'SeSecurityPrivilege'
        Operator = 'subsetof'; Expected = @('Administrators') }

    # --- WN11-00-*: system, inventory, and installed software ---
    'WN11-00-000005' = @{ Applicability = @{ DomainJoined = $true }
        Type = 'All'; Checks = @(
        @{ Type = 'Cim'; ClassName = 'Win32_OperatingSystem'; Property = 'Caption';        Operator = 'regex'; Expected = 'Enterprise' }
        @{ Type = 'Cim'; ClassName = 'Win32_OperatingSystem'; Property = 'OSArchitecture'; Operator = 'regex'; Expected = '64' }
    )}
    'WN11-00-000010' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Cim'; Namespace = 'root\CIMV2\Security\MicrosoftTpm'; ClassName = 'Win32_Tpm'
           Property = 'IsEnabled_InitialValue';   Operator = 'eq'; Expected = $true }
        @{ Type = 'Cim'; Namespace = 'root\CIMV2\Security\MicrosoftTpm'; ClassName = 'Win32_Tpm'
           Property = 'IsActivated_InitialValue'; Operator = 'eq'; Expected = $true }
        @{ Type = 'Cim'; Namespace = 'root\CIMV2\Security\MicrosoftTpm'; ClassName = 'Win32_Tpm'
           Property = 'SpecVersion';              Operator = 'regex'; Expected = '^2\.0' }
    )}
    'WN11-00-000020' = @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
        Name = 'UEFISecureBootEnabled'; Operator = 'eq'; Expected = 1 }
    # UseAdvancedStartup, plus either PIN form; 2 is the network-unlock variant.
    'WN11-00-000031' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'; Name = 'UseAdvancedStartup'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'; Name = 'UseTPMPIN';    Operator = 'in'; Expected = @(1,2) }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'; Name = 'UseTPMKeyPIN'; Operator = 'in'; Expected = @(1,2) }
        )}
    )}
    # 22H2 build 22621.380 or greater. UBR is compared separately only when the
    # build is exactly 22621; a later build satisfies the requirement outright.
    'WN11-00-000040' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; Name = 'CurrentBuild'; Operator = 'ge'; Expected = 22622 }
        @{ Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; Name = 'CurrentBuild'; Operator = 'eq'; Expected = 22621 }
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; Name = 'UBR';          Operator = 'ge'; Expected = 380 }
        )}
    )}
    'WN11-00-000045' = @{ Type = 'Cim'; Namespace = 'root\SecurityCenter2'; ClassName = 'AntiVirusProduct'
        Property = 'displayName'; Operator = 'exists'; Expected = $true }
    # Only system-created shares is NA per the check text, which the reviewer
    # decides; the share inventory is supplied so they need not go look.
    'WN11-00-000060' = @{ Type = 'Manual'
        Question = 'Do any non-system-created shares exist, and if so are their share and NTFS permissions restricted to the groups that require access? (ADMIN$, C$ and IPC$ alone are Not Applicable.)'
        Evidence = @{ Type = 'Cim'; ClassName = 'Win32_Share'; Property = 'Name' } }
    'WN11-00-000065' = @{ Type = 'LocalAccount'; Scope = 'User'; Property = 'StaleNames'; ThresholdDays = 35
        Operator = 'setequals'; Expected = @() }
    'WN11-00-000070' = @{ Type = 'Manual'
        Question = 'Are all members of the local Administrators group accounts responsible for administering this system? (The built-in Administrator and required administrative accounts are not a finding.)'
        Evidence = @{ Type = 'LocalAccount'; Scope = 'Group'; Name = 'Administrators'; Property = 'Members' } }
    # An empty group is explicitly not a finding, but a populated one is only a
    # finding if the members are not backup-specific - which cannot be read.
    'WN11-00-000075' = @{ Type = 'Manual'
        Question = 'If the Backup Operators group has members, is each one an account used specifically for backup functions rather than for normal user tasks? (An empty group is not a finding.)'
        Evidence = @{ Type = 'LocalAccount'; Scope = 'Group'; Name = 'Backup Operators'; Property = 'Members' } }
    'WN11-00-000080' = @{ Applicability = @{ HypervisorPresent = $true }
        Type = 'Manual'
        Question = 'Are all members of the Hyper-V Administrators group authorized to create or run virtual machines, and documented with the ISSM/ISSO?'
        Evidence = @{ Type = 'LocalAccount'; Scope = 'Group'; Name = 'Hyper-V Administrators'; Property = 'Members' } }
    'WN11-00-000085' = @{ Applicability = @{ DomainJoined = $true }
        Type = 'LocalAccount'; Scope = 'User'; Property = 'EnabledNames'
        Operator = 'subsetof'; Expected = @('Administrator','Guest','DefaultAccount','defaultuser0','WDAGUtilityAccount') }
    'WN11-00-000090' = @{ Type = 'LocalAccount'; Scope = 'User'; Property = 'NonExpiringNames'
        Operator = 'setequals'; Expected = @() }
    # Non-privileged groups must hold no more than read and execute.
    'WN11-00-000095' = @{ Type = 'Acl'
        Path = @('C:\', '%ProgramFiles%', '%SystemRoot%')
        AllowedPrincipals = @('NT AUTHORITY\SYSTEM','BUILTIN\Administrators','CREATOR OWNER','NT SERVICE\TrustedInstaller','APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES','APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES')
        MaxRights = @('ReadAndExecute','Read','ExecuteFile','Synchronize','ReadData','ReadAttributes','ReadExtendedAttributes','ReadPermissions','ListDirectory','Traverse') }
    'WN11-00-000100' = @{ Type = 'All'; Checks = @(
        @{ Type = 'OptionalFeature'; FeatureName = 'IIS-WebServerRole';       Operator = 'notin'; Expected = @('Enabled') }
        @{ Type = 'OptionalFeature'; FeatureName = 'IIS-HostableWebCore';     Operator = 'notin'; Expected = @('Enabled') }
    )}
    'WN11-00-000105' = @{ Type = 'Path'; Path = '%SystemRoot%\System32\snmp.exe';   Operator = 'eq'; Expected = $false }
    'WN11-00-000110' = @{ Type = 'OptionalFeature'; FeatureName = 'SimpleTCP';      Operator = 'notin'; Expected = @('Enabled') }
    'WN11-00-000115' = @{ Type = 'Path'; Path = '%SystemRoot%\System32\telnet.exe'; Operator = 'eq'; Expected = $false }
    'WN11-00-000120' = @{ Type = 'Path'; Path = '%SystemRoot%\System32\tftp.exe';   Operator = 'eq'; Expected = $false }
    # Searching every drive for *.p12/*.pfx is unbounded work with a documented
    # exception list, so it stays a question rather than a guess.
    'WN11-00-000130' = @{ Type = 'Manual'
        Question = 'Do any .p12 or .pfx certificate installation files exist on any drive? (Application-required .p12 files documented with the ISSO are not a finding.)' }
    'WN11-00-000135' = @{ Type = 'Service'; Name = 'mpssvc'; Property = 'State'; Operator = 'eq'; Expected = 'Running' }
    'WN11-00-000140' = @{ Applicability = @{ DomainJoined = $true }
        Type = 'Manual'
        Question = 'Are inbound firewall exceptions limited to authorized remote management hosts, scoped by remote IP and applied to all profiles?' }
    'WN11-00-000155' = @{ Applicability = @{ OsBuildBelow = 26100 }
        Type = 'OptionalFeature'; FeatureName = 'MicrosoftWindowsPowerShellV2*'; Operator = 'notin'; Expected = @('Enabled') }
    # NA when the two registry-based SMBv1 rules are already configured; this
    # gate checks the client-driver one of the pair.
    'WN11-00-000160' = @{ Applicability = @{ RegistryValueEquals = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'; Name = 'Start'; Value = 4 } }
        Type = 'OptionalFeature'; FeatureName = 'SMB1Protocol'; Operator = 'notin'; Expected = @('Enabled') }
    'WN11-00-000230' = @{ Applicability = @{ BluetoothPresent = $true }
        Type = 'Manual'
        Question = 'Is "Alert me when a new Bluetooth device wants to connect" enabled in Bluetooth settings?' }
    'WN11-00-000240' = @{ Type = 'Manual'
        Question = 'Does organizational policy prohibit administrative accounts from using internet-facing applications such as browsers and email, with defined exceptions for local service administration?' }
    'WN11-00-000260' = @{ Applicability = @{ DomainJoined = $true }
        Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
        Name = 'Type'; Operator = 'eq'; Expected = 'NT5DS' }

    # --- WN11-SO-000280: local administrator password age ---
    # NA when no local administrator account is enabled. LAPS policy state is
    # checked alongside the password age the STIG names.
    'WN11-SO-000280' = @{ Applicability = @{ LocalAdminEnabled = $true }
        Type = 'All'; Checks = @(
        @{ Type = 'LocalAccount'; Scope = 'User'; Name = 'Administrator'; Property = 'PasswordAgeDays'; Operator = 'le'; Expected = 60 }
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config'; Name = 'PasswordAgeDays'; Operator = 'le'; Expected = 60 }
    )}
}

# Auto-generated from DISA Windows 11 STIG V2R8 check-content (adversarially verified). Registry + AuditPolicy checks; UserRight/Service/manual rules are Not_Reviewed pending engine support.
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
    'WN11-UR-000005' = @{ Type = 'UserRight'; Privilege = 'SeTrustedCredManAccessPrivilege'; Operator = 'setequals'; Expected = @() }
    'WN11-UR-000015' = @{ Type = 'UserRight'; Privilege = 'SeTcbPrivilege';                   Operator = 'setequals'; Expected = @() }
    'WN11-UR-000025' = @{ Type = 'UserRight'; Privilege = 'SeInteractiveLogonRight';          Operator = 'setequals'; Expected = @('Administrators','Users') }
    'WN11-UR-000030' = @{ Type = 'UserRight'; Privilege = 'SeBackupPrivilege';                Operator = 'setequals'; Expected = @('Administrators') }
    'WN11-UR-000035' = @{ Type = 'UserRight'; Privilege = 'SeSystemtimePrivilege';            Operator = 'setequals'; Expected = @('Administrators','LOCAL SERVICE') }
    'WN11-UR-000040' = @{ Type = 'UserRight'; Privilege = 'SeCreatePagefilePrivilege';        Operator = 'setequals'; Expected = @('Administrators') }
    'WN11-UR-000045' = @{ Type = 'UserRight'; Privilege = 'SeCreateTokenPrivilege';           Operator = 'setequals'; Expected = @() }
    'WN11-UR-000050' = @{ Type = 'UserRight'; Privilege = 'SeCreateGlobalPrivilege';          Operator = 'setequals'; Expected = @('Administrators','LOCAL SERVICE','NETWORK SERVICE','SERVICE') }
    'WN11-UR-000055' = @{ Type = 'UserRight'; Privilege = 'SeCreatePermanentPrivilege';       Operator = 'setequals'; Expected = @() }
    'WN11-UR-000065' = @{ Type = 'UserRight'; Privilege = 'SeDebugPrivilege';                 Operator = 'setequals'; Expected = @('Administrators') }
    'WN11-UR-000095' = @{ Type = 'UserRight'; Privilege = 'SeEnableDelegationPrivilege';      Operator = 'setequals'; Expected = @() }
    'WN11-UR-000100' = @{ Type = 'UserRight'; Privilege = 'SeRemoteShutdownPrivilege';        Operator = 'setequals'; Expected = @('Administrators') }
    'WN11-UR-000120' = @{ Type = 'UserRight'; Privilege = 'SeLoadDriverPrivilege';            Operator = 'setequals'; Expected = @('Administrators') }
    'WN11-UR-000125' = @{ Type = 'UserRight'; Privilege = 'SeLockMemoryPrivilege';            Operator = 'setequals'; Expected = @() }
    'WN11-UR-000140' = @{ Type = 'UserRight'; Privilege = 'SeSystemEnvironmentPrivilege';     Operator = 'setequals'; Expected = @('Administrators') }
    'WN11-UR-000145' = @{ Type = 'UserRight'; Privilege = 'SeManageVolumePrivilege';          Operator = 'setequals'; Expected = @('Administrators') }
    'WN11-UR-000150' = @{ Type = 'UserRight'; Privilege = 'SeProfileSingleProcessPrivilege';  Operator = 'setequals'; Expected = @('Administrators') }
    'WN11-UR-000160' = @{ Type = 'UserRight'; Privilege = 'SeRestorePrivilege';               Operator = 'setequals'; Expected = @('Administrators') }
    'WN11-UR-000165' = @{ Type = 'UserRight'; Privilege = 'SeTakeOwnershipPrivilege';         Operator = 'setequals'; Expected = @('Administrators') }
    # --- Service ---
    'WN11-00-000175' = @{ Type = 'Service'; Name = 'seclogon'; Operator = 'eq'; Expected = 'Disabled' }
}

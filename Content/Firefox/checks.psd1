# Mozilla Firefox STIG V6R9 content pack (benchmark date 30 Sep 2026).
# NOT DISA content; verify against the official release before relying on results.
# Hand-authored: policy name and required value from DISA's about:policies check-content,
# registry location/type from Mozilla's policy-templates windows/firefox.admx.
#
# Every check reads HKLM\SOFTWARE\Policies\Mozilla\Firefox and requires the value present.
# Firefox reads HKCU first, then HKLM; an HKLM policy replaces the HKCU one whole, and a
# GPO policy name beats the same name in distribution\policies.json (CombinedProvider in
# EnterprisePoliciesParent.sys.mjs). So a present HKLM value is what Firefox enforces; a
# policy set only by HKCU or policies.json reads absent here and fails closed.
#
# Booleans are REG_DWORD 0/1. String enums (SSLVersionMin, Autoplay Default) use a
# case-sensitive regex because Firefox's enum match is case-sensitive.
# Preferences rules are Manual: the registry may hold them as JSON or as nested keys.
# Omitted (Not_Reviewed): 000001 version, 000006 MIME actions, 000016 DoD root certs.
@{
    'FFOX-00-000002' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'SSLVersionMin'; Operator = 'regex'; Expected = '(?-i)^tls1\.[23]\z' }
    'FFOX-00-000003' = @{ Type = 'Manual'
        Question = 'Does about:policies show Preferences with "security.default_personal_cert" Value "Ask Every Time" and Status "locked"? If not, this is a finding. Evidence, in order: (1) whether the key HKLM\SOFTWARE\Policies\Mozilla\Firefox\Preferences exists; (2) the JSON value named Preferences on ...\Mozilla\Firefox; (3) the value named "security.default_personal_cert" under ...\Firefox\Preferences. When the Preferences key exists, Firefox builds the policy from that key and ignores (2); a value named after the pref there (legacy ADMX form) is set and locked without a Status.'
        Evidence = @{ Type = 'All'; Checks = @(
            @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Preferences'; Operator = 'eq'; Expected = $true }
            @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'Preferences'; Operator = 'exists'; Expected = $true }
            @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Preferences'; Name = 'security.default_personal_cert'; Operator = 'exists'; Expected = $true }
        )} }
    'FFOX-00-000004' = @{ Type = 'Manual'
        Question = 'Does about:policies show Preferences with "browser.search.update" Value false and Status "locked"? If not, this is a finding. Evidence, in order: (1) whether the key HKLM\SOFTWARE\Policies\Mozilla\Firefox\Preferences exists; (2) the JSON value named Preferences on ...\Mozilla\Firefox; (3) the value named "browser.search.update" under ...\Firefox\Preferences. When the Preferences key exists, Firefox builds the policy from that key and ignores (2); a value named after the pref there (legacy ADMX form) is set and locked without a Status.'
        Evidence = @{ Type = 'All'; Checks = @(
            @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Preferences'; Operator = 'eq'; Expected = $true }
            @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'Preferences'; Operator = 'exists'; Expected = $true }
            @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Preferences'; Name = 'browser.search.update'; Operator = 'exists'; Expected = $true }
        )} }
    'FFOX-00-000005' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'ExtensionUpdate'; Operator = 'eq'; Expected = 0 }
    'FFOX-00-000007' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'DisableFormHistory'; Operator = 'eq'; Expected = 1 }
    'FFOX-00-000008' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'PasswordManagerEnabled'; Operator = 'eq'; Expected = 0 }
    'FFOX-00-000009' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking'; Name = 'Default'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\PopupBlocking'; Name = 'Locked'; Operator = 'eq'; Expected = 1 }
    )}
    'FFOX-00-000010' = @{ Type = 'Manual'
        Question = 'Does about:policies show Preferences with "dom.disable_window_move_resize" Value true and Status "locked"? If not, this is a finding. Evidence, in order: (1) whether the key HKLM\SOFTWARE\Policies\Mozilla\Firefox\Preferences exists; (2) the JSON value named Preferences on ...\Mozilla\Firefox; (3) the value named "dom.disable_window_move_resize" under ...\Firefox\Preferences. When the Preferences key exists, Firefox builds the policy from that key and ignores (2); a value named after the pref there (legacy ADMX form) is set and locked without a Status.'
        Evidence = @{ Type = 'All'; Checks = @(
            @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Preferences'; Operator = 'eq'; Expected = $true }
            @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'Preferences'; Operator = 'exists'; Expected = $true }
            @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Preferences'; Name = 'dom.disable_window_move_resize'; Operator = 'exists'; Expected = $true }
        )} }
    'FFOX-00-000011' = @{ Type = 'Manual'
        Question = 'Does about:policies show Preferences with "dom.disable_window_flip" Value true and Status "locked"? If not, this is a finding. Evidence, in order: (1) whether the key HKLM\SOFTWARE\Policies\Mozilla\Firefox\Preferences exists; (2) the JSON value named Preferences on ...\Mozilla\Firefox; (3) the value named "dom.disable_window_flip" under ...\Firefox\Preferences. When the Preferences key exists, Firefox builds the policy from that key and ignores (2); a value named after the pref there (legacy ADMX form) is set and locked without a Status.'
        Evidence = @{ Type = 'All'; Checks = @(
            @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Preferences'; Operator = 'eq'; Expected = $true }
            @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'Preferences'; Operator = 'exists'; Expected = $true }
            @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Preferences'; Name = 'dom.disable_window_flip'; Operator = 'exists'; Expected = $true }
        )} }
    'FFOX-00-000013' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\InstallAddonsPermission'; Name = 'Default'; Operator = 'eq'; Expected = 0 }
    'FFOX-00-000014' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'DisableTelemetry'; Operator = 'eq'; Expected = 1 }
    'FFOX-00-000015' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'DisableDeveloperTools'; Operator = 'eq'; Expected = 1 }
    'FFOX-00-000017' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown'; Name = 'Cache'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown'; Name = 'Cookies'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown'; Name = 'Downloads'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown'; Name = 'FormData'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown'; Name = 'Sessions'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown'; Name = 'History'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown'; Name = 'OfflineApps'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown'; Name = 'SiteSettings'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\SanitizeOnShutdown'; Name = 'Locked'; Operator = 'eq'; Expected = 1 }
    )}
    'FFOX-00-000018' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'DisableForgetButton'; Operator = 'eq'; Expected = 1 }
    'FFOX-00-000019' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'DisablePrivateBrowsing'; Operator = 'eq'; Expected = 1 }
    'FFOX-00-000020' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'SearchSuggestEnabled'; Operator = 'eq'; Expected = 0 }
    'FFOX-00-000021' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Permissions\Autoplay'; Name = 'Default'; Operator = 'regex'; Expected = '(?-i)^block-audio-video\z' }
    'FFOX-00-000022' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'NetworkPrediction'; Operator = 'eq'; Expected = 0 }
    'FFOX-00-000023' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection'; Name = 'Fingerprinting'; Operator = 'eq'; Expected = 1 }
    'FFOX-00-000024' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection'; Name = 'Cryptomining'; Operator = 'eq'; Expected = 1 }
    'FFOX-00-000025' = @{ Type = 'Manual'
        Question = 'Does about:policies show Preferences with "browser.contentblocking.category" Value "strict" and Status "locked"? If not, this is a finding. Evidence, in order: (1) whether the key HKLM\SOFTWARE\Policies\Mozilla\Firefox\Preferences exists; (2) the JSON value named Preferences on ...\Mozilla\Firefox; (3) the value named "browser.contentblocking.category" under ...\Firefox\Preferences. (4) ...\Firefox\EnableTrackingProtection\Category. When the Preferences key exists, Firefox builds the policy from that key and ignores (2); a value named after the pref there (legacy ADMX form) is set and locked without a Status. Firefox applies EnableTrackingProtection Category after Preferences, so (4) must also be absent or "strict"; any other value (e.g. "standard") is a finding.'
        Evidence = @{ Type = 'All'; Checks = @(
            @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Preferences'; Operator = 'eq'; Expected = $true }
            @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'Preferences'; Operator = 'exists'; Expected = $true }
            @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Preferences'; Name = 'browser.contentblocking.category'; Operator = 'exists'; Expected = $true }
            @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EnableTrackingProtection'; Name = 'Category'; Operator = 'exists'; Expected = $true }
        )} }
    'FFOX-00-000026' = @{ Type = 'Manual'
        Question = 'Does about:policies show Preferences with "extensions.htmlaboutaddons.recommendations.enabled" Value false and Status "locked"? If not, this is a finding. Evidence, in order: (1) whether the key HKLM\SOFTWARE\Policies\Mozilla\Firefox\Preferences exists; (2) the JSON value named Preferences on ...\Mozilla\Firefox; (3) the value named "extensions.htmlaboutaddons.recommendations.enabled" under ...\Firefox\Preferences. When the Preferences key exists, Firefox builds the policy from that key and ignores (2); a value named after the pref there (legacy ADMX form) is set and locked without a Status.'
        Evidence = @{ Type = 'All'; Checks = @(
            @{ Type = 'Path'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Preferences'; Operator = 'eq'; Expected = $true }
            @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'Preferences'; Operator = 'exists'; Expected = $true }
            @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\Preferences'; Name = 'extensions.htmlaboutaddons.recommendations.enabled'; Operator = 'exists'; Expected = $true }
        )} }
    'FFOX-00-000027' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DisabledCiphers'; Name = 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'; Operator = 'eq'; Expected = 1 }
    'FFOX-00-000028' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\UserMessaging'; Name = 'ExtensionRecommendations'; Operator = 'eq'; Expected = 0 }
    # DISA's names (Pocket, SponsoredPocket, Snippets), as the legacy CustomizeFirefoxHome ADMX policy writes them.
    # Firefox applies Stories/SponsoredStories after Pocket/SponsoredPocket to the same prefs, so they must not be on.
    'FFOX-00-000029' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome'; Name = 'Stories'; Operator = 'eq'; Expected = 0; AbsentIsPass = $true }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome'; Name = 'SponsoredStories'; Operator = 'eq'; Expected = 0; AbsentIsPass = $true }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome'; Name = 'Search'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome'; Name = 'TopSites'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome'; Name = 'SponsoredTopSites'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome'; Name = 'Pocket'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome'; Name = 'SponsoredPocket'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome'; Name = 'Highlights'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome'; Name = 'Snippets'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\FirefoxHome'; Name = 'Locked'; Operator = 'eq'; Expected = 1 }
    )}
    'FFOX-00-000033' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'; Name = 'Enabled'; Operator = 'eq'; Expected = 0 }
    'FFOX-00-000034' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'DisableFirefoxAccounts'; Operator = 'eq'; Expected = 1 }
    'FFOX-00-000036' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'DisableFeedbackCommands'; Operator = 'eq'; Expected = 1 }
    'FFOX-00-000037' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EncryptedMediaExtensions'; Name = 'Enabled'; Operator = 'eq'; Expected = 0 }
        @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\EncryptedMediaExtensions'; Name = 'Locked'; Operator = 'eq'; Expected = 1 }
    )}
    'FFOX-00-000039' = @{ Type = 'Registry'; NameCase = 'Exact'; Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'; Name = 'DisableFirefoxStudies'; Operator = 'eq'; Expected = 1 }
}

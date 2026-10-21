# Microsoft Windows Defender Firewall with Advanced Security STIG V2R2 content pack
# (benchmark date 09 Nov 2023). NOT DISA content; verify against the official
# release before relying on results. Hand-authored from each rule's Manual XCCDF
# check-content; a wrong path or value here is a silent false Pass.
#
# Most rules read "if the policy value exists and is not as specified, finding;
# if it does not exist, verify the local FirewallPolicy value". That is modelled
# as Any(policy ok, All(policy absent, local ok)), so a present-but-wrong policy
# value fails even when the local value is compliant. The Private profile's
# local key is StandardProfile.
#
# Rules that say "if the profile is not enabled (see V-1741x), this is also a
# finding" AND that profile's EnableFirewall check into the rule. "Not a member
# of a domain -> NA" uses the DomainJoined fact.
#
# Composite rules have no automated remediation (the planner reports Manual).
@{
    'WNFWA-000001' = @{ Applicability = @{ DomainJoined = $true }; Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
        )}
    )}
    'WNFWA-000002' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
        )}
    )}
    'WNFWA-000003' = @{ Type = 'Any'; Checks = @(
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
        @{ Type = 'All'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
            @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
        )}
    )}
    'WNFWA-000004' = @{ Applicability = @{ DomainJoined = $true }; Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'DefaultInboundAction'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'DefaultInboundAction'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'; Name = 'DefaultInboundAction'; Operator = 'eq'; Expected = 1 }
            )}
        )}
    )}
    'WNFWA-000005' = @{ Applicability = @{ DomainJoined = $true }; Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'DefaultOutboundAction'; Operator = 'eq'; Expected = 0 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'DefaultOutboundAction'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'; Name = 'DefaultOutboundAction'; Operator = 'eq'; Expected = 0 }
            )}
        )}
    )}
    'WNFWA-000009' = @{ Applicability = @{ DomainJoined = $true }; Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; Name = 'LogFileSize'; Operator = 'ge'; Expected = 16384 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; Name = 'LogFileSize'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging'; Name = 'LogFileSize'; Operator = 'ge'; Expected = 16384 }
            )}
        )}
    )}
    'WNFWA-000010' = @{ Applicability = @{ DomainJoined = $true }; Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; Name = 'LogDroppedPackets'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; Name = 'LogDroppedPackets'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging'; Name = 'LogDroppedPackets'; Operator = 'eq'; Expected = 1 }
            )}
        )}
    )}
    'WNFWA-000011' = @{ Applicability = @{ DomainJoined = $true }; Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; Name = 'LogSuccessfulConnections'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; Name = 'LogSuccessfulConnections'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging'; Name = 'LogSuccessfulConnections'; Operator = 'eq'; Expected = 1 }
            )}
        )}
    )}
    'WNFWA-000012' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'DefaultInboundAction'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'DefaultInboundAction'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'; Name = 'DefaultInboundAction'; Operator = 'eq'; Expected = 1 }
            )}
        )}
    )}
    'WNFWA-000013' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'DefaultOutboundAction'; Operator = 'eq'; Expected = 0 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'DefaultOutboundAction'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'; Name = 'DefaultOutboundAction'; Operator = 'eq'; Expected = 0 }
            )}
        )}
    )}
    'WNFWA-000017' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name = 'LogFileSize'; Operator = 'ge'; Expected = 16384 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name = 'LogFileSize'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging'; Name = 'LogFileSize'; Operator = 'ge'; Expected = 16384 }
            )}
        )}
    )}
    'WNFWA-000018' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name = 'LogDroppedPackets'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name = 'LogDroppedPackets'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging'; Name = 'LogDroppedPackets'; Operator = 'eq'; Expected = 1 }
            )}
        )}
    )}
    'WNFWA-000019' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name = 'LogSuccessfulConnections'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name = 'LogSuccessfulConnections'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging'; Name = 'LogSuccessfulConnections'; Operator = 'eq'; Expected = 1 }
            )}
        )}
    )}
    'WNFWA-000020' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'DefaultInboundAction'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'DefaultInboundAction'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'; Name = 'DefaultInboundAction'; Operator = 'eq'; Expected = 1 }
            )}
        )}
    )}
    'WNFWA-000021' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'DefaultOutboundAction'; Operator = 'eq'; Expected = 0 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'DefaultOutboundAction'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'; Name = 'DefaultOutboundAction'; Operator = 'eq'; Expected = 0 }
            )}
        )}
    )}
    'WNFWA-000027' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name = 'LogFileSize'; Operator = 'ge'; Expected = 16384 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name = 'LogFileSize'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging'; Name = 'LogFileSize'; Operator = 'ge'; Expected = 16384 }
            )}
        )}
    )}
    'WNFWA-000028' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name = 'LogDroppedPackets'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name = 'LogDroppedPackets'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging'; Name = 'LogDroppedPackets'; Operator = 'eq'; Expected = 1 }
            )}
        )}
    )}
    'WNFWA-000029' = @{ Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name = 'LogSuccessfulConnections'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name = 'LogSuccessfulConnections'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging'; Name = 'LogSuccessfulConnections'; Operator = 'eq'; Expected = 1 }
            )}
        )}
    )}
    # No local fallback: the policy value must exist.
    'WNFWA-000024' = @{ Applicability = @{ DomainJoined = $true }; Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'AllowLocalPolicyMerge'; Operator = 'eq'; Expected = 0 }
    )}
    'WNFWA-000025' = @{ Applicability = @{ DomainJoined = $true }; Type = 'All'; Checks = @(
        @{ Type = 'Any'; Checks = @(
            @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            @{ Type = 'All'; Checks = @(
                @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'EnableFirewall'; Operator = 'exists'; Expected = $false }
                @{ Type = 'Registry'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'; Name = 'EnableFirewall'; Operator = 'eq'; Expected = 1 }
            )}
        )}
        @{ Type = 'Registry'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name = 'AllowLocalIPsecPolicyMerge'; Operator = 'eq'; Expected = 0 }
    )}
    # Rule-scope review cannot be judged locally. NA for non-domain hosts; NA for
    # servers is not modelled (no server fact), so a domain server reads Not_Reviewed.
    'WNFWA-000100' = @{ Applicability = @{ DomainJoined = $true }; Type = 'Manual'
        Question = 'Is this a domain workstation whose inbound firewall exception rules allow only authorized management systems and remote management hosts (for example, limited by remote IP scope)? Mark NA if this system is a server.' }
}

# woscap bundled STIG-source manifest (Phase 2).
#
# This is a BEST-EFFORT pointer file: benchmark name -> direct DISA archive URL.
# It is NOT DISA content and woscap never redistributes STIG files. `Save-WoscapStigContent`
# consults this map ONLY when the operator omits -Url; an explicit -Url always overrides it.
#
# DISA URLs change every revision, so entries here go stale by nature. Update them as new
# revisions publish, or just pass -Url. Keys must be safe path segments (letters, digits,
# dot, dash, underscore) and should match the Content\<benchmark> pack names.
@{
    # Windows 11 manual STIG, V2R11 (benchmark date 2026-09-30). The Url follows the V2R8
    # host/path scheme with the local archive's file name; it was NOT verified online.
    # Hashtable form: pinned Url (best-effort, goes stale) + ScrapePattern used only when the
    # operator passes -AllowScrape to resolve the newest revision from the DISA downloads page.
    Windows11 = @{
        Url           = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R11_STIG.zip'
        ScrapePattern = 'Microsoft Windows 11 STIG'
    }

    # Microsoft Edge application STIG. Verified current at V2R5 on 2026-07-18. Pack: Content\Edge.
    Edge = @{
        Url           = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Edge_V2R5_STIG.zip'
        ScrapePattern = 'Microsoft Edge STIG'
    }

    # Google Chrome application STIG. Verified current at V2R11 on 2026-07-18. Pack: Content\Chrome.
    Chrome = @{
        Url           = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Google_Chrome_V2R11_STIG.zip'
        ScrapePattern = 'Google Chrome'
    }

    # Microsoft Windows Defender Firewall with Advanced Security STIG, V2R2 (benchmark date
    # 2023-11-09). Pack: Content\DefenderFirewall. The Url uses the host/path scheme above with the
    # local archive's file name; it was NOT verified online.
    DefenderFirewall = @{
        Url           = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Defender_Firewall_V2R2_STIG.zip'
        ScrapePattern = 'Windows[ _]Defender[ _]Firewall'
    }

    # Microsoft Defender Antivirus STIG, V2R10 (benchmark date 2026-09-30). Pack:
    # Content\DefenderAntivirus. The Url uses the host/path scheme above with the local
    # archive's file name; it was NOT verified online.
    DefenderAntivirus = @{
        Url           = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Defender_Antivirus_V2R10_STIG.zip'
        ScrapePattern = 'Defender[ _]Antivirus'
    }

    # Mozilla Firefox STIG, V6R9 (benchmark date 2026-09-30). Pack: Content\Firefox. The Url
    # uses the host/path scheme above with the local archive's file name; it was NOT verified online.
    Firefox = @{
        Url           = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MOZ_Firefox_V6R9_STIG.zip'
        ScrapePattern = 'Mozilla[ _]Firefox|MOZ_Firefox'
    }

    # Adobe Acrobat Reader DC Continuous Track STIG, V2R1 (benchmark date 2021-07-23). Pack:
    # Content\AcrobatReader. The Url uses the host/path scheme above with the local archive's
    # file name; it was NOT verified online. The pattern takes only the Continuous manual STIG:
    # not Acrobat Pro, the Classic Track, or any SCAP/Benchmark archive.
    AcrobatReader = @{
        Url           = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Adobe_Acrobat_Reader_DC_Continuous_V2R1_STIG.zip'
        ScrapePattern = '(?is)^(?!.*(?:SCAP|Benchmark)).*Acrobat[ _]Reader[ _]DC[ _]Continuous'
    }
}

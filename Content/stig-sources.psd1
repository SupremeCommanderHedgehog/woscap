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
    # Windows 11 manual STIG. Verified current at V2R8 (released 2026-05-19) on 2026-07-16.
    # Hashtable form: pinned Url (best-effort, goes stale) + ScrapePattern used only when the
    # operator passes -AllowScrape to resolve the newest revision from the DISA downloads page.
    Windows11 = @{
        Url           = 'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V2R8_STIG.zip'
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
}

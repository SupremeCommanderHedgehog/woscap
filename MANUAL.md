# woscap — User & Developer Manual

**Windows OS SCAP** — a Windows PowerShell 5.1 auditor for DISA STIG
compliance. This manual documents how to install, run, and extend `woscap`, and
how the engine works internally.

> **Scope of this document.** This manual describes the code **as it exists
> today** (module version `0.1.0`). Where a capability is part of the approved
> design but not yet implemented, it is called out explicitly under
> [Roadmap & not-yet-implemented](#12-roadmap--not-yet-implemented). The
> authoritative design is
> [`docs/superpowers/specs/2026-07-11-woscap-stig-scanner-design.md`](docs/superpowers/specs/2026-07-11-woscap-stig-scanner-design.md).

---

## Table of contents

1. [What woscap does](#1-what-woscap-does)
2. [Requirements](#2-requirements)
3. [Installation](#3-installation)
4. [Quick start](#4-quick-start)
5. [Obtaining an XCCDF benchmark](#5-obtaining-an-xccdf-benchmark)
6. [Public cmdlets](#6-public-cmdlets)
7. [Output formats](#7-output-formats)
8. [Exception / environment profiles](#8-exception--environment-profiles)
9. [Content packs — authoring checks](#9-content-packs--authoring-checks)
10. [Architecture & internals](#10-architecture--internals)
11. [Development](#11-development)
12. [Roadmap & not-yet-implemented](#12-roadmap--not-yet-implemented)
13. [Design principles / guarantees](#13-design-principles--guarantees)
14. [License](#14-license)

---

## 1. What woscap does

`woscap` evaluates a Windows endpoint's security configuration against a DISA
STIG benchmark and reports compliance. It is built for **both DoD and
private/commercial** environments, which have different risk tolerances — the
same checks run everywhere, and per-environment deviations are documented
transparently through [exception profiles](#8-exception--environment-profiles).

It uses a **hybrid** model:

- **Rule metadata** (V-ID, SV-ID, STIG ID, severity, title, discussion, check
  text, fix text, CCIs) is parsed from the operator-supplied DISA **XCCDF** file
  — so the tool stays aligned with the authoritative rule set.
- **Check logic** is hand-authored in the module as compact **declarative
  descriptors** (with a scriptblock escape hatch for complex rules) — so it stays
  maintainable and reviewable.

### How settings are read

The management consoles `gpedit.msc` and `secpol.msc` are non-scriptable GUIs and
are **never invoked**. Settings are read from their realized, scriptable
surfaces — exactly the surfaces DISA STIG check text is written against:

| Policy area | Read via | Helper |
|---|---|---|
| Administrative Templates | Registry (`HKLM`/`HKCU\...\Policies`) | `Get-RegValue` |
| Account policy / security options | `secedit.exe /export` → parsed INF | `Get-SecEditSetting` |
| User Rights Assignment | `secedit` INF `[Privilege Rights]` | `Get-UserRight` |
| Advanced Audit Policy | `auditpol /get /category:*` | `Get-AuditPolicy` |
| Service start mode / state | `Win32_Service` (CIM) | `Get-ServiceState` |
| File-system ACLs | `Get-Acl` | `Get-AclSetting` |

---

## 2. Requirements

- **Windows PowerShell 5.1** (the manifest pins `PowerShellVersion = '5.1'`).
  The audited-endpoint engine is **zero external dependency** — it uses only
  in-box primitives.
- **Administrative rights** on the audited host. `secedit`, `auditpol`, and many
  policy registry keys require an elevated session to read reliably.
- An **XCCDF benchmark file** you supply (see [section 5](#5-obtaining-an-xccdf-benchmark)).
  woscap never redistributes DISA content.
- **Dev-only** (not required to run): `Pester` ≥ 5.5 and `PSScriptAnalyzer` for
  the test/lint harness.

---

## 3. Installation

`woscap` is a standard script module. There is no installer — clone or copy the
repository and import the manifest.

```powershell
# From the repository root:
Import-Module .\woscap.psd1 -Force

# Confirm the public surface:
Get-Command -Module woscap
# Invoke-WoscapScan
# Export-WoscapResult
```

The module loader (`woscap.psm1`) dot-sources every `*.ps1` under `Private/` and
`Public/`, then exports **only** the public function names — private helpers
never leak into the caller's session. `$PSScriptRoot` is captured as
`$script:WoscapModuleRoot` so bundled content packs under `Content/` resolve
regardless of the working directory.

---

## 4. Quick start

```powershell
Import-Module .\woscap.psd1 -Force

# 1. Run a scan against the bundled Windows 11 content pack.
#    -XccdfPath is the DISA "manual" XCCDF you downloaded.
$results = Invoke-WoscapScan -XccdfPath .\U_MS_Windows_11_STIG_V2R8_Manual-xccdf.xml

# 2. The console prints a status summary; $results is RuleResult[] for pipelines.
$results | Where-Object Status -eq 'Open' | Format-Table StigId, Severity, Title

# 3. Export to any supported format.
$results | Export-WoscapResult -Format cklb -Path .\scan.cklb
$results | Export-WoscapResult -Format html -Path .\scan.html
```

With an exception profile applied:

```powershell
$results = Invoke-WoscapScan `
    -XccdfPath .\...xccdf.xml `
    -ProfilePath .\Profiles\example.psd1 `
    -JsonPath   .\raw-results.json
```

---

## 5. Obtaining an XCCDF benchmark

`woscap` **consumes an XCCDF file you supply**; it does not ship or download DISA
content.

1. Download the STIG `.zip` for your target from DISA
   (public.cyber.mil → STIGs).
2. Extract it and locate the **manual** XCCDF — the file named like
   `U_MS_Windows_11_STIG_V<ver>_Manual-xccdf.xml`.
3. Pass that path to `-XccdfPath`.

The bundled content pack (`Content/Windows11/`) was authored against **DISA
Windows 11 STIG V2R8**. Use a matching XCCDF version for best rule coverage;
rules present in the XCCDF but without an authored check are reported
`Not_Reviewed` (never silently passed).

### 5.1 Downloading STIG content (operator-side)

`Save-WoscapStigContent` fetches a DISA STIG archive **from a URL you supply**,
extracts and validates the manual XCCDF, caches it under
`%LOCALAPPDATA%\woscap\content\<benchmark>\<revision>\`, and returns a path you
can hand straight to `Invoke-WoscapScan`.

```powershell
Invoke-WoscapScan -Benchmark Windows11 -XccdfPath (
    Save-WoscapStigContent -Benchmark Windows11 `
        -Url 'https://.../U_MS_Windows_11_STIG_V<n>R<m>.zip' `
        -AcceptDisaTerms)
```

Notes:

- **Operator-side only.** This runs on your control workstation, never on an
  audited endpoint. Scanning still works fully offline with a hand-supplied
  `-XccdfPath`; auto-download is never triggered implicitly by a scan.
- **`-AcceptDisaTerms` is required.** woscap does not bundle or redistribute DISA
  content; it only downloads, on demand, into an operator-local cache. Your use
  of that content is governed by DISA's own terms (public.cyber.mil).
- **Cache.** Content is cached per benchmark + revision under
  `%LOCALAPPDATA%\woscap\content\<benchmark>\<revision>\`. Pass `-Destination` to use a
  different cache root, or `-Force` to re-download an already-cached revision. The cache is
  operator-local and never committed to the repo. List what you have cached with
  `Get-WoscapBenchmark` (optionally `-Benchmark <name>` / `-Destination <root>`).
- **Resolving the URL.** If you omit `-Url`, woscap consults a small bundled, best-effort
  benchmark→URL manifest (`Content\stig-sources.psd1`). It is a pointer file, not DISA
  content, and goes stale as DISA publishes new revisions — an explicit `-Url` always wins.
  Opt-in DISA-page resolution is available via `-AllowScrape` (see *Keeping content current*
  below).
- **Remembering the terms.** `-AcceptDisaTerms` accepts DISA's terms for a single call and
  writes nothing. If you run without it interactively, woscap prompts once; on accept it
  drops a `.woscap-disa-accepted` marker under the cache root so later runs on that
  workstation aren't re-prompted. Unattended runs must pass `-AcceptDisaTerms` (there is no
  silent proceed).

#### Keeping content current (Phase 3)

`Save-WoscapStigContent` can resolve the newest revision from the public DISA
downloads page when you pass **`-AllowScrape`** and the benchmark has a
`ScrapePattern` in the bundled manifest (`Content/stig-sources.psd1`). Scraping
is **opt-in and best-effort**: it parses a public HTML page that has no stable
API and may break on site changes, so it never runs unless you ask, and it
falls back to a clear error when it cannot resolve. An explicit `-Url` always wins. With `-AllowScrape`, scraping the DISA page takes precedence over the manifest's pinned `Url` (which becomes the fallback when the scrape finds nothing); without `-AllowScrape`, the pinned `Url` is used directly.

Manifest entries may be either a direct URL string or a hashtable:

```powershell
@{
    Windows11 = @{
        Url           = 'https://.../U_MS_Windows_11_V2R8_STIG.zip'  # pinned, best-effort
        ScrapePattern = 'Microsoft Windows 11 STIG'                  # used only with -AllowScrape
    }
}
```

**`Update-WoscapBenchmark`** re-resolves and fetches the latest revision. With
no `-Benchmark` it refreshes every benchmark already in your cache, printing one
row per benchmark (`Updated` / `AlreadyCurrent` / `Failed` with a reason). A new
revision lands in a new `<benchmark>\<revision>\` folder; existing revisions are
untouched.

Because a bulk refresh fans out a live DISA scrape plus a download per cached
benchmark, each per-benchmark refresh is gated by `ShouldProcess` (High impact):
it prompts per benchmark by default — suppress with `-Confirm:$false`. Use
`-WhatIf` to preview which benchmarks would be re-resolved (one `WhatIf` row each)
without any network I/O; a benchmark you decline at the prompt is reported
`Skipped`.

```powershell
Update-WoscapBenchmark -AcceptDisaTerms -AllowScrape -WhatIf          # preview only — no downloads
Update-WoscapBenchmark -AcceptDisaTerms -AllowScrape -Confirm:$false  # refresh all, no prompts
Update-WoscapBenchmark -Benchmark Windows11 -AcceptDisaTerms          # prompts before download
```

Downloads are cheap on an unchanged cache: `Save-WoscapStigContent` issues a HEAD
`ETag` pre-check and, when the cached revision's stored ETag matches, returns the cached
XCCDF without re-downloading, unzipping, or re-parsing. Each revision's XCCDF content
SHA-256 is recorded in its `.woscap-content.json` sidecar (and surfaced as `ContentHash`
on `Get-WoscapBenchmark`), so a same-revision re-release — DISA re-publishing different
content under the same revision label — is detected by the changed content hash, the cache
is refreshed with the new bytes, and `Update-WoscapBenchmark` reports it as `Updated`.
Hashing the XCCDF (not the archive) keeps this stable across benign re-zips whose bytes
differ but whose content is identical. `-Force` bypasses the ETag short-circuit and always
re-downloads.

**`Remove-WoscapBenchmark`** prunes the operator-local cache. `-Benchmark` is
required (there is no whole-cache wipe). Without `-Revision` it removes the whole
benchmark subtree; with `-Revision` it removes just that revision. It supports
`-WhatIf`/`-Confirm` and prompts by default (High impact).

```powershell
Remove-WoscapBenchmark -Benchmark Windows11 -Revision 1 -WhatIf
Remove-WoscapBenchmark -Benchmark Windows11
```

Downloaded content is operator-local, uncommitted, and governed by DISA's terms.

---

## 6. Public cmdlets

Two cmdlets are exported today.

### `Invoke-WoscapScan`

Runs a scan and returns `RuleResult[]`.

```powershell
Invoke-WoscapScan
    -XccdfPath   <string>      # (required) path to the DISA XCCDF file
    [-Benchmark  <string>]     # content-pack name; default 'Windows11'
    [-ContentPath <string>]    # override content-pack dir; default Content/<Benchmark>
    [-ProfilePath <string[]>]  # one or more exception profiles (layered, last wins)
    [-ComputerName <string[]>] # remote hosts to scan over WinRM; omit/localhost = local
    [-Credential <pscredential>] # auth for remote hosts (default Negotiate/Kerberos)
    [-ThrottleLimit <int>]     # max hosts scanned in parallel (default 8)
    [-JsonPath   <string>]     # also write raw RuleResult[] JSON to this path
    [-Quiet]                   # suppress the console summary
```

Behaviour:

1. `Import-Xccdf` parses `-XccdfPath` → rule metadata.
2. `Import-ContentPack` loads the descriptors from `-ContentPath` (defaults to
   `<module>/Content/<Benchmark>`).
3. If `-ProfilePath` is given, `Import-ExceptionProfile` merges the profiles.
4. `Invoke-CheckEval` joins metadata + checks + exceptions → `RuleResult[]`.
5. If `-JsonPath` is given, the raw results are written as JSON (depth 6).
6. Unless `-Quiet`, a console summary prints per-status counts, Open CAT I, and
   the risk-accepted subset.
7. `RuleResult[]` is emitted to the pipeline.

#### Remote fleet scanning

Pass `-ComputerName` to scan one or more remote hosts over PowerShell
Remoting/WinRM. The XCCDF is parsed once on the control host; a **curated
module subset** — the manifest, the root module (`.psm1`), `Private/`,
`Public/`, and only the single relevant content pack — is shipped into each
session with `Copy-Item -ToSession` (not the whole module tree), and the engine
runs on the target. Per-host scan work then fans out **in parallel** through one
batched `Invoke-Command`, so the fleet is scanned concurrently rather than
host-by-host. Results aggregate into one `RuleResult[]` across the fleet, each
stamped with its `Host`.

```powershell
$results = Invoke-WoscapScan -XccdfPath .\...xccdf.xml `
    -ComputerName 'SRV01','SRV02' -Credential (Get-Credential)
```

- **Per-host isolation / fail-closed:** an unreachable or WinRM-disabled host
  yields a single `Not_Reviewed` result for that host (with the reason in
  `FindingDetails`) and never aborts the batch. Unreachable-host detection
  matches on the **normalized** host name, so a short-name-vs-FQDN difference
  (e.g. `SRV01` vs `SRV01.corp.example`) no longer false-flags a host that did
  in fact respond.
- **`-ThrottleLimit`** (default 8) bounds the parallel scan fan-out — it caps how
  many hosts are actively scanned at once through the batched `Invoke-Command`
  (it now throttles the real scan work, not just session creation).
  `localhost`, `.`, `127.0.0.1`, and the machine's own name are treated as the
  local (in-process) case — no remoting.
- **Prerequisite:** WinRM must be enabled on the targets (`Enable-PSRemoting`);
  woscap does not configure it.

### `Export-WoscapResult`

Renders `RuleResult[]` to a file in a chosen format. Accepts results from the
pipeline.

```powershell
Export-WoscapResult
    -Result <object[]>   # (required, pipeline) RuleResult[] from Invoke-WoscapScan
    -Format <string>     # (required) one of: cklb | ckl | csv | html | json
    -Path   <string>     # (required) output file path
```

Buffers all piped results, then dispatches to the matching reporter. Each format
is an isolated reporter reading the same `RuleResult[]`.

### `Show-WoscapGui`

Launches the interactive **Windows Forms** front-end. Takes no parameters — it
is a thin launcher over the cmdlets.

```powershell
Show-WoscapGui
```

The window lets an operator pick a benchmark + XCCDF, set targets (blank =
local; comma-separated hosts = remote over WinRM) and an optional exception
profile, tick **Use alternate credential** to prompt for credentials, then
**Run** a scan with a live progress bar. Results land in a grid filterable by
severity / status / free-text find, and **Export…** writes any supported format
via `Export-WoscapResult`. Each result row is **color-coded by status** (Open =
red, NotAFinding = green, Not_Applicable = gray, Not_Reviewed = amber) so
findings stand out at a glance, and the grid **resizes with the window** — drag
the frame larger to see more of the table. A **partial scan** (e.g. one
unreachable host among several) still shows the results that came back and
reports `Done (N warnings)` with the detail on hover — only a scan that returns
nothing raises a `Scan failed` dialog. The GUI holds **no** evaluation,
exception, or export logic of its own — every action calls the corresponding
cmdlet, so it can never diverge from the CLI.

**Requirements & boundaries:** needs an interactive desktop session (STA); it is
**not** available on Server Core / headless hosts. For unattended, headless, or
CI use, call `Invoke-WoscapScan` / `Export-WoscapResult` directly. Internally
the scan runs in a background runspace so the window stays responsive; the UI
layer lives in `Private/UI/` (builder `New-WoscapMainForm`, handler logic in
`WoscapGuiHandlers.ps1`) plus the public `Show-WoscapGui` launcher.

---

### `Invoke-WoscapRemediation`

Applies fixes for **Open** findings on the **local host**, then re-checks each
rule to confirm the fix took. This is woscap's only deliberate **write** path —
opt-in and confirmation-gated; the scan/audit path stays strictly read-only.

**Scope:** only **Registry** and **AuditPolicy** checks are auto-applied (exact
parity with the Ansible playbook emitter). Every other check type — UserRight,
Service, SecEdit, ScriptBlock, or a missing/incomplete descriptor — is reported
`State='Manual'` and never written.

**Gating:** the cmdlet declares `SupportsShouldProcess` with `ConfirmImpact='High'`,
so it prompts before each write by default.

| Parameter | Effect |
|---|---|
| `-Result <RuleResult[]>` | Open findings to remediate (accepts pipeline input from `Invoke-WoscapScan`). |
| `-Benchmark <name>` | Content pack supplying fix descriptors (default `Windows11`). |
| `-ContentPath <dir>` | Override the content-pack directory. |
| `-WhatIf` | Plan only — every automatable rule is reported `State='Planned'`; nothing is written. |
| `-Force` / `-Confirm:$false` | Apply without prompting (unattended). An explicit `-Confirm` still wins. |
| `-Quiet` | Suppress the console summary. |

**Auto re-check:** after applying a rule's fix, the same descriptor evaluator
re-runs and the outcome is reported in `After` — `NotAFinding` (fixed), `Open`
(still failing), or `Error`.

**Elevation:** writing registry / audit policy requires an elevated session. A
permission error on a single rule surfaces as `State='Failed'` (with the error in
`Detail`) and the batch continues — one failure never aborts the run.

```powershell
# Plan only — show what would change, write nothing:
Invoke-WoscapScan -XccdfPath .\U_MS_Windows_11_STIG_V2R8_Manual-xccdf.xml |
    Invoke-WoscapRemediation -WhatIf

# Apply unattended (run from an elevated shell), then review the report:
$fixes = Invoke-WoscapScan -XccdfPath .\U_MS_Windows_11_STIG_V2R8_Manual-xccdf.xml |
    Invoke-WoscapRemediation -Force
$fixes | Format-Table StigId, State, Before, After, Detail
```

Each result is a `RemediationResult`: `Host`, `StigId`, `Title`, `CheckType`,
`Action`, `State` (`Planned` / `Applied` / `Failed` / `Skipped` / `Manual`),
`Before`, `After`, `Detail`.

> **Known limitation (v1):** for an AuditPolicy subcategory with paired
> Success+Failure rules, the post-apply re-check verifies the subcategory's
> representative descriptor, not every contributing rule. **Out of scope:** remote
> fleet remediation, Service/UserRight/SecEdit application, and rollback/backup of
> prior values.

### `Get-WoscapIntegration`

Enumerates integration plugins (each a folder with a `plugin.psd1` manifest +
`implementation.ps1`) and reports whether each is `Conformant`. Accepts a
`-Path` that is either the integrations root or a single plugin folder;
malformed plugins are listed with `Conformant = $false` rather than hidden.

### `Import-WoscapIntegration`

Pull-side dispatch to a plugin's capability hooks: `-Targets` invokes
`Get-Targets`, `-Findings -Path <report>` invokes `Import-Findings`. Pass
`-CorrelateWith <RuleResult[]>` to join imported findings to same-host rule
results (matching CVE/CCE/CCI against rule CCIs) into a unified
`{ Results; Findings; Links }` view.

Host identity is resolved before correlating, so an OpenVAS finding whose
`<host>` is an **IP address** links to a STIG result keyed by **computername**.
Pass resolution hints via `-Config`:

- `HostMap` — an `@{ '<ip-or-alias>' = '<canonical name>' }` table (authoritative;
  any dictionary, including `[ordered]`, is accepted).
- `ResolveDns` — `$true` to allow best-effort reverse-DNS for unmapped IP hosts
  (opt-in; default off, so correlation does zero network I/O by default).

Hosts that resolve to the same identity correlate regardless of IP-vs-name
representation (matching is case-insensitive and treats a short name and its FQDN
as equal); an unresolvable host still surfaces its finding, just without a link
(fail-warn-only).

### `Export-WoscapIntegration`

Push-side dispatch: by default sends `-Result <RuleResult[]>` to a plugin's
`Export-Findings` hook; `-Remediation -Path <file>` invokes `New-Remediation`
to emit remediation content. Loader/dispatch failures warn and return nothing —
they never abort a scan.

### `Invoke-WoscapIntegration`

Trigger-side dispatch: invokes a plugin's `Invoke-ExternalScan` hook with the
supplied `-Config` hashtable, returning normalized findings. Currently the
OpenVAS plugin implements it — a live Greenbone/OpenVAS scan over GMP (see
[Live OpenVAS triggering (GMP)](#live-openvas-triggering-gmp)). An unresolved
integration or any hook failure warns and returns nothing — it never throws.

#### Bundled plugins

Three plugins ship under `Integrations/`. Core scanning never depends on any of
them, and a plugin failure only warns — it never aborts a scan.

| Plugin | Capabilities | `-Config` keys |
|---|---|---|
| **OpenVAS** | `Import-Findings`, `Invoke-ExternalScan` | ingest reads `-Path`; live GMP triggering reads `Server`, `Port` (default 9390), `Credential` (PSCredential), `Targets`, `ScanConfigId`, `ScannerId`, `PortListId` **or** `PortRange` (gvmd requires a port spec; default `PortRange` = `T:1-65535`), `SmbCredentialId` / `SshCredentialId` / `SshCredentialPort` (default 22) + `AliveTest` (for authenticated scans — e.g. a real Windows/SMB compliance scan), `PollSeconds` (default 15, clamped to ≥1), `TimeoutMinutes` (default 60), `SkipCertificateCheck`, `RequestTimeoutMs` (default 30000), `ReportTimeoutMs` (default 300000, for the possibly-large report fetch) |
| **Ansible** | `Get-Targets`, `New-Remediation`, `Export-Findings` | `Group` (inventory group filter); `Benchmark` / `ContentPath` (source of fix descriptors); `FactsPath` (facts output) |
| **Zabbix** | `Export-Findings`, `Get-Targets` | `Server`, `Port` (trapper, default 10051); `ApiUrl`, `Token` (JSON-RPC host inventory) |

- **OpenVAS** ingests a Greenbone/OpenVAS report XML into normalized findings and,
  with `-CorrelateWith`, cross-links them to STIG results on CVE/CCE/CCI — resolving
  IP-vs-computername hosts via the `-Config` `HostMap`/`ResolveDns` keys (#52). It can
  also **trigger a live scan over GMP** (`Invoke-WoscapIntegration`, #23) — see below.
- **Ansible** parses an INI or YAML inventory into a target list, and emits a
  remediation **playbook** (`win_regedit` / `win_audit_policy_system` / …) derived
  from the same check descriptors the engine evaluates. Rules with no automatable
  fix are emitted as `# manual:` comments, never silently dropped.
- **Zabbix** pushes per-host posture metrics (`woscap.open.cat1/2/3`,
  `compliance.pct`, exception counts) over the **Zabbix sender protocol** using
  in-box `System.Net.Sockets` — no `zabbix_sender` binary required.

```powershell
# Pull targets from an Ansible inventory, scan, push posture to Zabbix
$hosts = Import-WoscapIntegration -Integration Ansible -Targets `
    -Source .\inventory.ini -Config @{ Group = 'windows' }
$r = Invoke-WoscapScan -Benchmark Windows11 `
    -XccdfPath .\U_MS_Windows_11_STIG_V2R8_Manual-xccdf.xml -ComputerName $hosts
Export-WoscapIntegration -Integration Zabbix -Result $r -Config @{ Server = 'zbx.example.com' }

# Emit an Ansible remediation playbook for the open findings
Export-WoscapIntegration -Integration Ansible -Result $r -Remediation -Path .\remediate.yml
```

#### Live OpenVAS triggering (GMP)

Trigger a Greenbone/OpenVAS scan directly over **GMP** (Greenbone Management
Protocol — XML over a TLS socket, default port 9390) and get normalized findings
back, without a manual report export:

```powershell
$cred = Get-Credential            # gvmd username + password
Invoke-WoscapIntegration -Integration OpenVAS -Config @{
    Server               = 'gvm.example.local'
    Port                 = 9390            # optional (default 9390)
    Credential           = $cred
    Targets              = @('10.0.0.5', '10.0.0.6')
    ScanConfigId         = '<scan-config-uuid>'   # e.g. "Full and fast"
    ScannerId            = '<scanner-uuid>'        # e.g. the default OpenVAS scanner
    PortRange            = 'T:22,80,443'           # or PortListId = '<port-list-uuid>'; gvmd requires one
    PollSeconds          = 15              # optional (default 15, clamped to >= 1)
    TimeoutMinutes       = 60              # optional (default 60)
    SkipCertificateCheck = $true           # optional; accept a self-signed gvmd cert
    ReportTimeoutMs      = 300000          # optional; raise for very large reports
}
```

The call authenticates, creates a fresh target + task, starts the scan, polls
`get_tasks` until it completes (or reaches a terminal failure state, or
`TimeoutMinutes` elapses), fetches the full report (`details='1'`, all pages),
deletes the target + task it created, and returns findings in the **same shape as
file ingest** — so `-CorrelateWith` and the reporters work unchanged. Every
failure mode (unreachable host, rejected auth, GMP error status, terminal scan
state, poll timeout) emits a warning and returns no findings; it never throws or
aborts a surrounding scan. Transport uses in-box `System.Net.Sockets` / `SslStream`
only — no `gvm-tools` required.

For an **authenticated** scan (deep local checks — the usual case for a Windows
host), attach gvmd credential UUIDs and, for firewalled hosts that drop pings, a
permissive alive test:

```powershell
Invoke-WoscapIntegration -Integration OpenVAS -Config @{
    Server = 'gvm.example.local'; Credential = $cred; SkipCertificateCheck = $true
    Targets = @('10.0.0.20'); ScanConfigId = '<uuid>'; ScannerId = '<uuid>'
    PortRange       = 'T:135,139,445'          # SMB ports
    SmbCredentialId = '<gvmd-smb-credential-uuid>'
    SshCredentialId = '<gvmd-ssh-credential-uuid>'   # optional; SshCredentialPort defaults to 22
    AliveTest       = 'Consider Alive'         # host drops ICMP (e.g. Windows firewall)
}
```

**Authoring a plugin:** create `Integrations/<Name>/plugin.psd1` (declaring
`Name`, `Capabilities`, `Implementation`) and an `implementation.ps1` that returns
a hashtable mapping each declared hook to a scriptblock. The loader validates that
declared capabilities and implemented hooks agree (and that each is a known hook);
mismatches are rejected with a warning. `tests/helpers/Assert-WoscapPluginConformance.ps1`
is the shared conformance check.

---

## 7. Output formats

All reporters consume the same `RuleResult[]`; none can make posture look cleaner
than it is.

| Format | Reporter | Description |
|---|---|---|
| `cklb` | `Export-WoscapCklb` | STIG Viewer 3 checklist (JSON), `cklb_version 1.0`. Field-aligned to the CKLB schema; per-rule `status`, `comments` (exception justifications), `finding_details`, CCIs, UUIDs. |
| `ckl`  | `Export-WoscapCkl`  | Legacy STIG Viewer checklist (XML). |
| `csv`  | `Export-WoscapCsv`  | One row per rule: Host, Benchmark, BenchmarkVersion, StigId, GroupId, RuleId, Severity, Status, Title, Expected, Observed, Cci (`;`-joined), FindingDetails, Comments. UTF-8. |
| `html` | `Export-WoscapHtml` | Self-contained dashboard: summary cards (Open / NotAFinding / Not_Applicable / Not_Reviewed, plus Open CAT I/II/III) and a client-side **filterable** per-rule table, color-coded by status. HTML-escaped. |
| `json` | `Export-WoscapJson` | Raw `RuleResult[]` for pipelines/automation. |

All file writes go through the single `Write-WoscapText` helper.

### Status mapping (DISA convention)

The engine's internal `Result` maps to a DISA `Status` via
`ConvertTo-WoscapStatus`:

| Internal `Result` | `Status` |
|---|---|
| `Pass` | `NotAFinding` |
| `Fail` | `Open` |
| `NA` | `Not_Applicable` |
| `NotReviewed` | `Not_Reviewed` |
| `Error` | `Not_Reviewed` (detail carried in `FindingDetails`) |

A check **never** silently passes on error — errors and missing checks both land
as `Not_Reviewed`, keeping coverage gaps visible.

---

## 8. Exception / environment profiles

An **exception profile** is an org-owned `.psd1` file, keyed by STIG ID, applied
at scan time with `-ProfilePath`. Profiles are **layerable** — pass several and
later files override earlier keys (`Import-ExceptionProfile` merges in order). An
example lives at [`Profiles/example.psd1`](Profiles/example.psd1).

### The four exception types

| Type | Effect |
|---|---|
| `NotApplicable` | Rule marked `Not_Applicable`; justification into `Comments`. Not evaluated. |
| `AcceptedRisk` | Rule is **still evaluated**. If it fails it **stays `Open`**, tagged risk-accepted with justification. **A failure is never converted to a pass.** |
| `Override` | Re-evaluates the rule against a changed `Expected`/`Operator`, and/or changes `Severity`. Used when org policy is stricter/looser than the STIG floor, or to re-rate a CAT. |
| `Exclude` | Skips evaluation → `Not_Reviewed` with reason. Discouraged. |

### Example profile

```powershell
@{
    # Not applicable in this environment (documented).
    'WN11-00-000031' = @{ Type = 'NotApplicable'; Justification = 'No BitLocker here.'; Author = 'me'; Date = '2026-07-01' }

    # Documented accepted risk (still reported Open with the justification).
    'WN11-00-000165' = @{ Type = 'AcceptedRisk'; Justification = 'Legacy app needs SMBv1.'; Author = 'me'; Date = '2026-07-01'; Expires = '2027-07-01' }

    # Org policy stricter than the STIG floor (re-evaluate + downgrade CAT).
    'WN11-AU-000500' = @{ Type = 'Override'; Justification = 'Org requires 64MB app log.'; Author = 'me'; Date = '2026-07-01'; Operator = 'ge'; Expected = 65536; Severity = 'low' }

    # Handled by a separate process; excluded from this scan.
    'WN11-00-000210' = @{ Type = 'Exclude'; Justification = 'Bluetooth governed by MDM.'; Author = 'me'; Date = '2026-07-01' }
}
```

### Provenance & expiry (fail-closed)

Every applied exception is recorded on the result as an `Exception` record with
full provenance — `Type`, `Justification`, `Author`, `Date`, `Expires`
(`New-WoscapExceptionRecord`).

**Expired waivers fail closed.** `Test-WoscapExceptionActive` compares `Expires`
(date only) against a reference date; an expired *or* unparseable `Expires` makes
the exception **inactive**, so the rule is evaluated normally and a warning is
emitted. Stale risk acceptances therefore resurface instead of hiding findings.
A malformed (non-table) exception entry is likewise ignored with a warning.

---

## 9. Content packs — authoring checks

A content pack is a directory (default `Content/<Benchmark>/`) with up to two
files, both keyed by STIG ID and merged by `Import-ContentPack` (overrides win):

- **`checks.psd1`** — declarative descriptors (the common case).
- **`checks.overrides.ps1`** — returns a hashtable of scriptblock checks for
  rules that don't fit a declarative pattern (the escape hatch).

### Declarative descriptor schema

Each entry is a hashtable. Keys vary by `Type`; all types compare via an
`Operator` against `Expected` (except `ScriptBlock`).

```powershell
'WN11-AU-000010' = @{ Type='AuditPolicy'; Subcategory='Credential Validation'; Operator='includes'; Expected='Success' }
'WN11-CC-000005' = @{ Type='Registry'; Path='HKLM:\SOFTWARE\...\Personalization'; Name='NoLockScreenCamera'; Operator='eq'; Expected=1 }
'WN11-UR-000030' = @{ Type='UserRight'; Privilege='SeBackupPrivilege'; Operator='subsetof'; Expected=@('Administrators') }
'WN11-00-000175' = @{ Type='Service'; Name='seclogon'; Operator='eq'; Expected='Disabled' }
'WN11-CC-000075' = @{ Type='Cim'; Namespace='root\Microsoft\Windows\DeviceGuard'; ClassName='Win32_DeviceGuard'
                      Property='SecurityServicesRunning'; Operator='includes'; Expected=1 }
'WN11-00-000240' = @{ Type='Manual'; Question='Does policy prohibit admin web browsing?' }
```

#### Check types (`Type`) and their keys

| Type | Read helper | Descriptor keys |
|---|---|---|
| `Registry` | `Get-RegValue` | `Path`, `Name`; optional `AbsentIsPass` |
| `SecEdit` | `Get-SecEditSetting` | `Name`, `Section` (default `System Access`) |
| `UserRight` | `Get-UserRight` | `Privilege` (a `Se*` right); `Expected` is a principal list, compared **as SIDs** via `Resolve-PrincipalSid` |
| `AuditPolicy` | `Get-AuditPolicy` | `Subcategory` |
| `Service` | `Get-ServiceState` | `Name`, `Property` (default `StartMode`) |
| `Cim` | `Get-CimSetting` | `ClassName`, `Property`; optional `Namespace` (default `root\CIMV2`), `Filter` |
| `Certificate` | `Get-CertificateSetting` | `Store`, `Match` (`Subject`/`Issuer`/`Thumbprint` regexes); optional `RequireUnexpired`. **Observed is a match count**, so use `ge 1` for must-be-present and `eq 0` for must-be-absent |
| `Acl` | `Test-AclCompliance` | `Path` (one or many; filesystem or `HK*:`), `AllowedPrincipals`, optional `MaxRights` |
| `OptionalFeature` | `Get-OptionalFeatureState` | `FeatureName` (wildcards allowed); observed is `Enabled`/`Disabled`/`Absent` |
| `Path` | `Test-PathPresence` | `Path` (environment variables expanded); observed is a boolean |
| `LocalAccount` | `Get-LocalAccountSetting` | `Scope` (`User`/`Group`), `Property`, optional `Name`, `ThresholdDays` |
| `All` / `Any` | — | `Checks` — an array of child descriptors, evaluated recursively |
| `Manual` | — | `Question`, optional `Evidence` (a child descriptor whose reading is reported but never judged) |
| `ScriptBlock` | — | `Script` — a scriptblock returning one of `Pass`/`Fail`/`NA`/`NotReviewed`/`Error` |

`LocalAccount` pairs `Scope` with `Property`, and the two are cross-validated:
`User` accepts `EnabledNames`, `NonExpiringNames`, `StaleNames` and
`PasswordAgeDays`; `Group` accepts `Members` and requires `Name`.

#### Composites (`All` / `Any`)

`All` passes when every child passes; `Any` when at least one does. They cover
GPO-or-Intune alternate paths, policies written to several hives, and numeric
ranges that exclude a sentinel value:

```powershell
# "60 days or less, and 0 (never expires) is also a finding"
'WN11-AC-000025' = @{ Type='All'; Checks=@(
    @{ Type='SecEdit'; Name='MaximumPasswordAge'; Operator='ne'; Expected=0 }
    @{ Type='SecEdit'; Name='MaximumPasswordAge'; Operator='le'; Expected=60 }
)}
```

A child may carry its own `Applicability`. Children that resolve to `NA` or
`NotReviewed` are **excluded from the verdict** rather than counted as
non-passing, so an `All` containing a `Manual` child still passes when its
automated children pass. When every child is `NA` the composite is `NA`; when
some are `NotReviewed` it is `NotReviewed`. An `Error` in any child fails the
composite, so a permission failure never reads as a pass.

#### Applicability

An optional `Applicability` hashtable marks a rule Not Applicable from
**machine-observable facts** before any reading is taken:

| Predicate | Argument |
|---|---|
| `DomainJoined`, `TpmPresent`, `CameraPresent`, `BluetoothPresent`, `HypervisorPresent`, `LocalAdminEnabled` | `$true` / `$false` |
| `OsBuildAtLeast`, `OsBuildBelow` | a build number |
| `RegistryValueEquals` | `@{ Path; Name; Value }` — a **negative** gate: NA *when* the value matches |

Conditions a machine cannot know — classified network, PAW designation, an
approved site deviation — belong in an [exception profile](#8-exception--environment-profiles),
not here. An unknown predicate is an error, never a silent pass, and a predicate
whose own read fails yields `Error` rather than `NA` (an `NA` would drop the rule
from scoring entirely, hiding it as effectively as a false pass).

> **Fail-closed invariant.** Every read helper distinguishes *"read failed"* from
> *"read succeeded and found nothing"*. A failed read returns an internal
> unreadable sentinel that `Test-Descriptor` renders as `Error`. This matters
> because several operators treat an empty reading as compliant on purpose
> (`subsetof`, `setequals @()`, `notin`, `exists:$false`, `AbsentIsPass`) — so
> collapsing the two would score an unread machine as compliant.
> `tests/Checks/FailClosed.Tests.ps1` asserts this as a cross-product of every
> reading type against every such operator.

#### Operators (`Compare-WoscapValue`)

| Operator | Meaning |
|---|---|
| `eq` / `ne` | equal / not equal |
| `ge` / `le` | numeric ≥ / ≤ (null on either side → fail) |
| `in` | observed is one of the expected set |
| `includes` | observed collection contains expected (used for `auditpol` `Success`/`Failure`) |
| `regex` | observed matches the expected pattern |
| `exists` | value present (or absent, if `Expected` is falsy) |
| `notin` | observed is **not** in the expected set |
| `setequals` | observed set equals expected set (order/dupes ignored) |
| `subsetof` | every observed member is in `Expected` — *"only assigned to X"*. An empty observed set is compliant |
| `supersetof` | every expected member is in `Observed` — *"X must be defined"* |
| `sequence` | ordered equality, for `REG_MULTI_SZ` where the order is the policy |

> **`subsetof` vs `setequals` vs `supersetof`.** DISA user-rights rules read
> *"if any groups or accounts **other than** the following..."*, which a host
> satisfies by granting the right to **fewer** principals than listed — that is
> `subsetof`. Deny-rights rules read *"the following groups **must be defined**"*,
> which is the opposite test, `supersetof`. `setequals` demands both at once and
> is wrong for either; it is kept for genuine exact-set comparisons.

### Scriptblock escape hatch

For multi-condition or computed rules, author them in `checks.overrides.ps1`:

```powershell
@{
    'WNTEST-00-000020' = @{ Type = 'ScriptBlock'; Script = { 'Pass' } }
}
```

The scriptblock uses the same read-only helpers and returns a status string.

### Current Windows 11 coverage

**All 256 rules of the DISA Win11 STIG V2R8 have a deliberate entry: 248
automated and 8 explicitly `Manual`.**

The 8 manual rules are the ones whose finding condition cannot be read from the
machine — whether a camera is physically covered, whether the members of the
local Administrators group are authorized, an all-drive `.p12` search, and so on.
Each carries the interview question, and most also carry automated evidence (a
share list, a group's membership) so the reviewer does not have to go and look
it up. **A deliberately-manual rule is not the same as an unauthored one**, and
`Content/Windows11/coverage.psd1` plus
`tests/Content/Windows11.Coverage.Tests.ps1` enforce that distinction: the pack
must match the manifest exactly, the two must agree on which rules are manual,
and every manual entry must carry a question.

The manifest holds rule IDs only — identifiers, not DISA check content — so it
is committed even though the licensed XCCDF is not. A further test reconciles
the manifest against the real XCCDF and is skipped where that file is absent, so
drift is caught on any machine that has the content.

#### Known limitation: `HKCU` rules

`WN11-UC-000020` and `WN11-CC-000390` read `HKCU`, which resolves to the hive of
the account **running the scan**, not the audited user's. Reading every loaded
user hive is a separate change; until then, treat those two results as applying
to the scanning account only.

### Application packs (Edge, Chrome)

Two application STIG packs ship alongside Windows 11, both **auto-generated from
the DISA Manual XCCDF check-content and adversarially verified** (the raw XCCDFs are
never committed):

- **`Content/Edge/checks.psd1`** — Microsoft Edge STIG V2R5, 52 of 61 rules as
  `Registry` checks. Generated by `ConvertTo-WoscapCheckDescriptor`, which reads the
  registry key/value/expected the Edge check-text states inline.
- **`Content/Chrome/checks.psd1`** — Google Chrome STIG V2R11, 37 of 46 rules.
  Chrome's check-text uses the `chrome://policy` method and states no registry path,
  so `ConvertTo-WoscapChromePolicyDescriptor` takes the policy name and required value
  from the STIG and maps them onto Chrome's documented policy key
  `HKLM\SOFTWARE\Policies\Google\Chrome\<PolicyName>`.

Both generators are **fail-closed**: a rule is only emitted when a single scalar
registry value can be read unambiguously from the prose. List/allowlist policies,
organization-specific strings, multi-value ("1 or 2"), version cross-references, and
manual rules are omitted and surface as `Not_Reviewed` — never guessed. Scan with
`Invoke-WoscapScan -XccdfPath <edge-or-chrome-xccdf> -Benchmark Edge` (or `Chrome`);
fetch the content via `Save-WoscapStigContent -Benchmark Edge -AllowScrape`.

---

## 10. Architecture & internals

### Module layout (implemented)

```
woscap/
├─ woscap.psd1 / woscap.psm1        # manifest + loader (exports Public only)
├─ Public/
│   ├─ Invoke-WoscapScan.ps1         # main entry (local scan)
│   └─ Export-WoscapResult.ps1       # results → cklb/ckl/csv/html/json
├─ Private/
│   ├─ Parser/   Import-Xccdf.ps1     # XCCDF → rule-metadata objects (no eval)
│   ├─ Content/  Import-ContentPack.ps1
│   ├─ Engine/   Invoke-CheckEval.ps1 # join metadata + checks + exceptions
│   ├─ Checks/                        # descriptor evaluator + read helpers
│   │   ├─ Test-Descriptor.ps1        #   interprets one descriptor
│   │   ├─ Compare-WoscapValue.ps1    #   the operator set
│   │   ├─ Get-RegValue / Get-SecEditSetting / Get-AuditPolicy /
│   │   │   Get-UserRight / Get-ServiceState / Get-AclSetting
│   │   ├─ Invoke-SecEditExport / ConvertFrom-SecEditInf
│   │   ├─ Invoke-AuditPol / ConvertFrom-AuditPolCsv
│   │   └─ Resolve-PrincipalSid
│   ├─ Model/
│   │   ├─ New-WoscapResult.ps1        # builds a RuleResult (plain data)
│   │   └─ ConvertTo-WoscapStatus.ps1  # Result → DISA Status
│   ├─ Exception/                      # profile load + resolve + provenance + expiry
│   │   ├─ Import-ExceptionProfile.ps1
│   │   ├─ Resolve-WoscapException.ps1
│   │   ├─ Test-WoscapExceptionActive.ps1
│   │   └─ New-WoscapExceptionRecord.ps1
│   └─ Report/   Export-WoscapCklb / -Ckl / -Csv / -Html / -Json
│                 + ConvertTo-CklbStatus + Write-WoscapText
├─ Content/Windows11/  checks.psd1     # first content pack
├─ Profiles/           example.psd1    # sample exception profile
└─ tests/                              # Pester suite + fixtures
```

### Scan flow

```
Invoke-WoscapScan
  └─ Import-Xccdf        (XCCDF file → rule metadata pscustomobject[])
  └─ Import-ContentPack  (checks.psd1 [+ overrides] → descriptor hashtable)
  └─ Import-ExceptionProfile  (optional, merged .psd1 profiles)
  └─ Invoke-CheckEval    (per rule:)
        ├─ Resolve-WoscapException  (active exception for this StigId?)
        ├─ NotApplicable/Exclude → short-circuit result
        ├─ no descriptor          → NotReviewed ("no check authored")
        ├─ Override               → clone descriptor, patch Expected/Operator/Severity
        ├─ Test-Descriptor        → read helper + Compare-WoscapValue → Pass/Fail/Error
        └─ New-WoscapResult       → RuleResult (with Status + Exception record)
  └─ (optional JSON) + console summary + emit RuleResult[]
```

### The `RuleResult` object

`New-WoscapResult` emits a **plain `pscustomobject`** (no live methods, so it
survives PSRemoting serialization). Fields:

| Field | Source | Notes |
|---|---|---|
| `Host` | runtime | defaults to `$env:COMPUTERNAME` |
| `Benchmark`, `BenchmarkVersion` | XCCDF | scan context |
| `StigId`, `GroupId` (V-…), `RuleId` (SV-…), `Cci[]` | XCCDF | identity / traceability |
| `GroupTitle` | XCCDF | XCCDF Group title (the SRG name); threaded into the CKLB/CKL reporters (`group_title` / `Group_Title`) |
| `Severity` (`high`/`medium`/`low` ↔ CAT I/II/III) | XCCDF | may be overridden by profile |
| `Title`, `Discussion`, `CheckText`, `FixText` | XCCDF | carried into reports |
| `CheckType` | content pack | Registry/SecEdit/AuditPolicy/UserRight/Service/ScriptBlock |
| `Expected`, `Observed` | descriptor / read helper | what was compared |
| `Result` | engine | `Pass`/`Fail`/`NA`/`NotReviewed`/`Error` (internal) |
| `Status` | mapped | DISA status (see [§7](#status-mapping-disa-convention)) |
| `FindingDetails` | auto | e.g. `Expected [1]; observed [0].` |
| `Comments` | auto | exception justification when applicable |
| `Exception` | applied waiver | `{Type, Justification, Author, Date, Expires}` or `$null` |

### XCCDF parsing (`Import-Xccdf`)

Loads the file as `[xml]`, validates the root element is `Benchmark` (fails fast
otherwise), resolves the document namespace dynamically, and walks every
`Group/Rule`. Per rule it extracts: `GroupId`, `RuleId`, `StigId` (from
`Rule/version`), `Severity`, `Title`, `Discussion`, `CheckText`
(`check/check-content`), `FixText`, and `Cci[]` (`ident` nodes), plus the
benchmark title/version.

### Read helpers (all read-only)

- `Get-RegValue` — `Get-ItemProperty`; returns `$null` if the key/value is
  absent (drives `exists`/`eq` semantics).
- `Get-SecEditSetting` / `Get-UserRight` — `secedit /export` to a temp INF
  (`Invoke-SecEditExport`), parsed by `ConvertFrom-SecEditInf`; user rights come
  from the `[Privilege Rights]` section.
- `Get-AuditPolicy` — `auditpol /get /category:* /r` (`Invoke-AuditPol`) parsed
  by `ConvertFrom-AuditPolCsv`; returns the subcategory's inclusion setting.
- `Get-ServiceState` — `Win32_Service` via CIM → `{Name, StartMode, State}`.
- `Get-AclSetting` — `Get-Acl`-based ACL reads.
- `Resolve-PrincipalSid` — maps well-known principal names to static SIDs
  (locale-proof), falling back to `NTAccount.Translate`.

---

## 11. Development

### Running the tests

Tests use **Pester ≥ 5.5**. Read helpers are exercised against mocked
`secedit`/`auditpol`/registry output; the descriptor evaluator across the full
operator matrix; the parser against a fixture XCCDF; the engine join logic;
every exception type (including the "AcceptedRisk never flips fail→pass" and
"expired fails closed" invariants); and each reporter.

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -Force -SkipPublisherCheck
Import-Module Pester -MinimumVersion 5.5.0

$config = New-PesterConfiguration
$config.Run.Path = './tests'
$config.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $config
```

Notable tests:
- `tests/ReadOnly.Tests.ps1` — asserts the audit path performs **no writes**.
- `tests/Module.Tests.ps1` — module import / export surface.
- `tests/Integration/RealXccdf.Smoke.Tests.ps1` — smoke test against a real XCCDF.

### Linting

`PSScriptAnalyzer` is run with the repo's `PSScriptAnalyzerSettings.psd1`.
`PSUseCompatibleSyntax` targets **5.1 as the floor** with **7.4 also listed**, so
PS7-only syntax is flagged before it can creep into the 5.1 endpoint runtime. The
default rule set runs too; CI fails only on `Error`-severity findings.

```powershell
Install-Module PSScriptAnalyzer -Scope CurrentUser -Force
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
```

### Continuous integration

`.github/workflows/ci.yml` runs on push/PR to `main`, on `windows-latest`, in two
jobs:

- **lint** — PSScriptAnalyzer; fails the build on any `Error`-severity finding.
- **test** — Pester ≥ 5.5 over `./tests`, uploading `testResults.xml`.

### Coding conventions

- Public cmdlets live in `Public/`, one function per file named after the file;
  everything else goes in `Private/` and stays unexported.
- Keep the audited-endpoint path **5.1-safe and zero-dependency**.
- Read helpers must remain **read-only**. Fail closed — never mark a rule
  compliant on error or on a missing check.

---

## 12. Roadmap & not-yet-implemented

The following are part of the approved design but **not present in the code
today**. Do not assume they work:

| Area | Status |
|---|---|
| **Integration plugin layer** (contract + loader/dispatcher + `Get-`/`Import-`/`Export-WoscapIntegration`) | **Shipped** (#16). The capability-hook contract, fail-warn-only loader/dispatcher, and the three cmdlets exist. |
| **Bundled integration plugins** (OpenVAS / Ansible / Zabbix under `Integrations/`) | **Shipped** (#17 / #18 / #19). Report ingest + correlation, inventory targets + playbook remediation, and sender-protocol metrics. Live OpenVAS GMP triggering (`Invoke-WoscapIntegration`) shipped (#23). |
| **Remediation** (`Invoke-WoscapRemediation`, gated in-place fixes, Ansible remediation-as-code) | **Partially shipped** (#22). `Invoke-WoscapRemediation` applies **Registry + AuditPolicy** fixes on the **local** host, `-WhatIf`/`-Confirm`-gated (`ConfirmImpact='High'`), with auto re-check; other check types report `Manual`. Ansible remediation-as-code (playbook emitter) shipped in #18. Remote fleet remediation, Service/UserRight/SecEdit application, and rollback remain Phase 4. |
| **`Get-WoscapBenchmark`** (list cached downloaded STIG content) | **Shipped** (#53). Lists the operator-local download cache (`Save-WoscapStigContent` output) by benchmark + revision; supports `-Benchmark` / `-Destination` filters. |
| **Additional content packs** (Server 2019/2022 MS+DC) | **Partially shipped.** Windows 11 is **complete at 256/256 rules** (248 automated, 8 manual, #70), and application packs for **Edge** and **Chrome** (#21) ship; Windows Server MS/DC packs remain. |

Per the roadmap, **Phase 2 is complete**: all five reporters, the
exception/profile system, remote fleet execution over WinRM
(`-ComputerName`), and the WinForms GUI (`Show-WoscapGui`) are all shipped,
on top of the Phase 0–1 skeleton/engine/first-benchmark/local-scan work.
**Phase 3 is complete**: the integration plugin layer — contract, loader/
dispatcher, and `Get-`/`Import-`/`Export-WoscapIntegration` (#16) — plus the
bundled OpenVAS (#17), Ansible (#18), and Zabbix (#19) plugins are all shipped.
Phase 4 is underway: gated in-place remediation for Registry/AuditPolicy on the
local host (`Invoke-WoscapRemediation`, #22) and live OpenVAS GMP triggering
(`Invoke-WoscapIntegration`, #23) are shipped. Windows 11 content
coverage is complete (256/256 rules, #70). Remaining Phase 4 work is content-pack
breadth for Server 2019/2022 and remote / rollback remediation.

---

## 13. Design principles / guarantees

- **Fail closed.** A rule is never silently marked compliant on error or a
  missing check — both become `Not_Reviewed`.
- **Zero dependency on the endpoint.** The engine uses only in-box PowerShell
  5.1 primitives; Pester/PSScriptAnalyzer are dev-only.
- **Read-only audit path.** The scan never writes to the audited system
  (enforced by `tests/ReadOnly.Tests.ps1`).
- **Never redistribute DISA content.** woscap consumes an XCCDF the operator
  supplies.
- **Transparent posture.** Exceptions are always recorded with provenance;
  expired waivers fail closed; `AcceptedRisk` never converts a failure to a pass.
- **Plain-data results.** `RuleResult` carries no live methods, so it round-trips
  cleanly through serialization (readying it for the future remoting path).

---

## 14. License

`woscap` is licensed under the **Apache License, Version 2.0** — see
[`LICENSE`](LICENSE). Apache-2.0 is a permissive license with an explicit patent
grant, chosen to keep the tool broadly adoptable across DoD and commercial
environments (including OEM/vendor integration) while giving contributors and
users defensive patent protection. Copyright © 2026 Patrick Connallon.

`woscap` never redistributes DISA content; the XCCDF benchmark you supply is
covered by DISA's own terms, not this license.

---

*This manual tracks module version `0.1.0`. Keep it updated as capabilities in
[section 12](#12-roadmap--not-yet-implemented) are implemented.*

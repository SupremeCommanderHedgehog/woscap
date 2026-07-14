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
'WN11-UR-000030' = @{ Type='UserRight'; Privilege='SeBackupPrivilege'; Operator='setequals'; Expected=@('Administrators') }
'WN11-00-000175' = @{ Type='Service'; Name='seclogon'; Operator='eq'; Expected='Disabled' }
```

#### Check types (`Type`) and their keys

| Type | Read helper | Descriptor keys |
|---|---|---|
| `Registry` | `Get-RegValue` | `Path`, `Name` |
| `SecEdit` | `Get-SecEditSetting` | `Name`, `Section` (default `System Access`) |
| `UserRight` | `Get-UserRight` | `Privilege` (a `Se*` right); `Expected` is a principal list, compared **as SIDs** via `Resolve-PrincipalSid` |
| `AuditPolicy` | `Get-AuditPolicy` | `Subcategory` |
| `Service` | `Get-ServiceState` | `Name`, `Property` (default `StartMode`) |
| `ScriptBlock` | — | `Script` — a scriptblock returning one of `Pass`/`Fail`/`NA`/`NotReviewed`/`Error` |

> **ACL note:** a `Get-AclSetting` read helper exists, but `Test-Descriptor`
> does **not** yet have an `ACL` case — an `ACL`-typed descriptor currently falls
> to the evaluator's default branch and returns `Error` (→ `Not_Reviewed`). ACL
> checks are not usable in a content pack yet.

#### Operators (`Compare-WoscapValue`)

| Operator | Meaning |
|---|---|
| `eq` / `ne` | equal / not equal |
| `ge` / `le` | numeric ≥ / ≤ (null on either side → fail) |
| `in` | observed is one of the expected set |
| `includes` | observed collection contains expected (used for `auditpol` `Success`/`Failure`) |
| `regex` | observed matches the expected pattern |
| `exists` | value present (or absent, if `Expected` is falsy) |
| `setequals` | observed set equals expected set (used by `UserRight`, order/dupes ignored) |

### Scriptblock escape hatch

For multi-condition or computed rules, author them in `checks.overrides.ps1`:

```powershell
@{
    'WNTEST-00-000020' = @{ Type = 'ScriptBlock'; Script = { 'Pass' } }
}
```

The scriptblock uses the same read-only helpers and returns a status string.

### Current Windows 11 coverage

`Content/Windows11/checks.psd1` implements ~163 rules across `Registry`,
`AuditPolicy`, `UserRight`, and `Service` types (DISA Win11 STIG V2R8). Rules
requiring check types not yet wired (e.g. ACL/manual rules) are left out and
surface as `Not_Reviewed`. The full XCCDF carries ~256 rules, so unauthored ones
are reported `Not_Reviewed` rather than silently passed.

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
| **Integrations** (OpenVAS / Ansible / Zabbix, `Import-/Export-WoscapIntegration`) | **Not implemented.** No `Integrations/` directory exists. |
| **Remediation** (`Invoke-WoscapRemediation`, gated in-place fixes, Ansible remediation-as-code) | **Not implemented** (Phase 4). |
| **`Get-WoscapBenchmark`** (list installed content packs) | **Not implemented.** |
| **Additional content packs** (Server 2019/2022 MS+DC, MS/third-party apps) | **Not implemented.** Windows 11 only. |

Per the roadmap, **Phase 2 is complete**: all five reporters, the
exception/profile system, remote fleet execution over WinRM
(`-ComputerName`), and the WinForms GUI (`Show-WoscapGui`) are all shipped,
on top of the Phase 0–1 skeleton/engine/first-benchmark/local-scan work.
Phases 3–4 (integrations, remediation) remain.

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

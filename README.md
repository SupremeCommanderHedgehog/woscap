# woscap

**Windows OS SCAP** — a Windows PowerShell auditor for DISA STIG compliance.

`woscap` evaluates Windows and application security configuration against DISA
STIG benchmarks and reports compliance, for both **DoD** and **private /
commercial** environments. It parses DISA's official **XCCDF** benchmark
metadata and applies hand-coded PowerShell check logic, so it stays aligned with
the authoritative rule set while remaining maintainable.

> **Status:** Design phase. See the design spec in
> [`docs/superpowers/specs/2026-07-11-woscap-stig-scanner-design.md`](docs/superpowers/specs/2026-07-11-woscap-stig-scanner-design.md).
> All work is tracked through [issues](../../issues) and the linked
> [project board](../../projects).

## Highlights

- **Windows PowerShell 5.1, zero external dependencies** on the audited endpoint.
- **Hybrid checks:** DISA XCCDF metadata + declarative check descriptors, with a
  scriptblock escape hatch for complex rules.
- **Local core + remote fleet** scanning over PowerShell Remoting/WinRM.
- **Reports:** STIG Viewer `.cklb`/`.ckl`, HTML, CSV/JSON, and pipeline objects.
- **Exception profiles:** layerable, provenance-tracked waivers/overrides so one
  engine serves a strict DoD baseline and a relaxed commercial one.
- **CLI and GUI:** cmdlets are the source of truth; a zero-dependency WinForms
  front-end drives the same cmdlets.
- **Integrations plugin layer:** OpenVAS (vuln correlation), Ansible (targets +
  remediation-as-code), Zabbix (monitoring/alerting).

## How settings are read

`gpedit.msc` and `secpol.msc` are non-scriptable GUIs and are never invoked.
Settings are read from their realized surfaces: the **registry** (Administrative
Templates), **`secedit.exe`** (account policy, security options, user rights),
and **`auditpol`** (Advanced Audit Policy) — which is how DISA STIG check text is
actually written.

## Roadmap

| Phase | Scope |
|---|---|
| 0 | Module skeleton, `RuleResult` model, read helpers, descriptor evaluator, test/lint harness |
| 1 | First benchmark end-to-end (Windows 11): XCCDF parser, content pack, engine, local scan |
| 2 | Reporting (cklb/ckl/HTML/CSV) + exception profiles + remote execution + WinForms GUI |
| 3 | Integrations: OpenVAS, Ansible, Zabbix |
| 4 | Breadth (Server 2019/2022, MS/third-party apps) + direct gated remediation |

## Content licensing

`woscap` never redistributes DISA content. It **consumes an XCCDF file you
supply** — the "manual" `*_xccdf.xml` from the DISA STIG download.

## License

[Apache-2.0](LICENSE).

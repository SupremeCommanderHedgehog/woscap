# Security Policy

`woscap` is a security auditing tool, so its own integrity matters. This policy
covers how to report vulnerabilities and the security guarantees the tool makes.

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities. Instead, use
GitHub's private vulnerability reporting:

1. Go to the **Security** tab → **Report a vulnerability**.
2. Provide a description, affected component, and reproduction steps.

You will receive an acknowledgement, and a fix or mitigation will be tracked
privately until disclosure.

## Security guarantees of the tool

- **Audit path is read-only.** The scanning/auditing path never modifies the
  target system; this is enforced by a test. Any state change is confined to the
  explicitly opt-in, `-WhatIf`/`-Confirm`-gated remediation feature.
- **Fail closed.** A rule is never reported compliant on a check error or a
  missing check — those become `Not_Reviewed`.
- **No silent suppression.** Exception profiles document deviations with
  provenance; an accepted-risk waiver never converts a failing rule to a pass.
- **Zero endpoint dependencies.** The target-side engine uses only in-box Windows
  PowerShell 5.1 primitives, reducing supply-chain surface on audited hosts.

## Supported versions

The project is pre-release; security fixes target the `main` branch.

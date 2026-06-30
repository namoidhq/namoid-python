# Security policy

This repository is part of [NamoID](https://namoid.in) — an identity provider,
so we take security seriously even in our client libraries and examples. If
you've found a vulnerability, please report it privately so we can fix it before
it gets exploited.

## Reporting a vulnerability

**Email:** `hello@namoid.in`

Please **do not** open a public GitHub issue for security reports.

Include:

- A clear description of the issue and where you found it (repo, file + line,
  package version, or a URL if it's a hosted surface).
- Reproduction steps — the minimum required for us to trigger it.
- Impact assessment: who is affected, what data is exposed, what capability is
  gained.
- Optional: a suggested fix.

We'll acknowledge within **48 hours** and give a triage decision within
**5 business days**. We'll credit you in the release notes if you'd like —
anonymous reports are welcome too.

## Scope

This repo ships client-side code (examples and/or SDKs). The most relevant
findings here are things like:

- Token or secret handling bugs in the SDK or example flows.
- Insecure defaults that could lead an integrator to leak credentials.
- Dependency vulnerabilities that affect how this code is actually used.

Findings against the NamoID hosted service itself (`*.id.namoid.in`,
`api.namoid.in`) are also welcome — email the same address with the details
above.

## Safe harbor

If you act in good faith — no data exfiltration beyond proof-of-concept, no
service disruption, no targeting of other people's accounts, and you give us
time to fix before disclosing — we won't pursue legal action against you.

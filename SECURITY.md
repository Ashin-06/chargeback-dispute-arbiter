# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately, through GitHub's private vulnerability
reporting on this repository (Security → Report a vulnerability) or by contacting the
maintainer, [@Ashin-06](https://github.com/Ashin-06), directly. Do not open a public issue.

Include what you found, how to reproduce it and what an attacker could do with it. You should
get an acknowledgement within 5 working days. Please give us 90 days to fix an issue before
disclosing it, and don't test against anyone else's deployment.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |
| < 1.0 | no (prototype releases) |

## Scope

In scope: the dispute API, evidence-packet verification (Merkle tree and Ed25519 check), the
reason-code rules, the dispute store, the container image and the CI configuration in this
repository. A way to make a forged or altered packet verify against the pinned merchant key is
the most serious class of report.

Out of scope: the truth of the evidence itself (the merchant signs its own records; see the
README's Limits), the card networks' own systems, and findings that need an already-compromised
host or a leaked API key with the matching role.

This project has **not** had an independent security review or penetration test.

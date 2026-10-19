# Security policy

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/dagoSte/rea-safe-agents/security/advisories/new)
to contact the maintainer privately. Do not put exploit details, credentials,
private inputs or transcripts in a public issue. For ordinary bugs and feature
requests, use [GitHub Issues](https://github.com/dagoSte/rea-safe-agents/issues).

Include the affected commit, host OS and Docker version, the relevant profile,
expected and observed behavior, and a minimal reproducer using inert data.
Describe the boundary crossed and the privileges needed. Do not test against
other people's machines or services. Reports are reviewed by the maintainer;
there is no guaranteed response time or paid bounty program.

## Supported code and fixes

Security maintenance targets the latest `main` revision. Older commits have no
separate maintenance promise. After any helper, image, deployment or host OS
change, repeat the verification required by [SETUP.md](SETUP.md). A failed check
does not authorize weaker isolation or host execution.

Confirmed vulnerabilities are addressed through reviewed fixes and regression
tests where practical. Coordinate disclosure through the private report so
that fixes and public advisories can describe the affected commits and remedies.

## Scope and known limits

Read the [security model](skills/rea-isolated/references/security-model.md),
[validation record](docs/validation.md), and [image findings](docs/image-audit.md).
The host controller, Docker and the relevant kernel/hypervisor remain trusted.
Approved content can reach the selected model provider. Windows Docker
integration is experimental. Known dependency findings remain; a successful
scan is not a claim of vulnerability-free software.

OpenSSF practice badges and automated scores describe their stated criteria.
They do not certify sandbox escape resistance or replace an independent audit.

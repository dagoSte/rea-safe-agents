# npm audit evidence

Audit date: **2026-10-18**. Both current committed lockfiles were resolved and
audited entirely inside the pinned Node Docker image: Node **24.22.0**, npm
**11.19.1**, Linux ARM64. No host npm or REA execution was used for these checks.
The locks include npm registry URLs and SHA-512 package integrity values.

## REA 6.7.0

- [Committed lockfile](../skills/rea-isolated/assets/package-lock.json). SHA-256: `d6def307433c5b534827ec5a9d0916574bddfa5de6bf3f9da0f93c1f6d217e20`.
- [Raw audit JSON](evidence/npm-audit-rea-6.7.0-locked-2026-10-18.json). Command: `npm audit --omit=dev --omit=optional --json`.
- npm vulnerability counts: informational 0, low 0, moderate 0, high 0, critical 0; **total 0**.
- npm dependency metadata: `{"prod":148,"dev":0,"optional":32,"peer":0,"peerOptional":0,"total":179}`.

## Codex 0.163.0 + Claude Code 2.1.302

- [Committed lockfile](../skills/rea-isolated/assets/agent/package-lock.json). SHA-256: `cc98cd76c1c4aedd0213175f35669a0618ebe9c79f6d9e03136d6d03f6d20090`.
- [Raw audit JSON](evidence/npm-audit-clients-locked-2026-10-18.json). Command: `npm audit --omit=dev --json`.
- npm vulnerability counts: informational 0, low 0, moderate 0, high 0, critical 0; **total 0**.
- npm dependency metadata: `{"prod":3,"dev":0,"optional":14,"peer":0,"peerOptional":0,"total":16}`.

The current Dockerfiles copy these manifests/locks and run `npm ci`, with
lifecycle scripts suppressed. REA omits optional dependencies. The client
image includes the native optional packages for its Linux architecture; the
lock also records other platform variants. npm's metadata categories include
those variants and must not be read as an installed-package count or SBOM.

## Scope

These reports cover the locked npm dependency trees and the indicated omit
policy. They do not scan OS apt packages, Docker, the kernel, REA/client source
for malicious behavior or undeclared flaws. A zero finding is not proof of
benign packages. The raw JSON records a dated registry response, not a
certification of all future builds.

The [official npm audit documentation](https://docs.npmjs.com/cli/v11/commands/npm-audit/)
explains registry advisory checks. Lock integrity protects consistency with
reviewed metadata; a compromised release already selected in a lock can pass.
Independent signature/provenance verification and image-wide vulnerability
scanning remain outside the completed evidence. Runtime containment is still
required. OS apt package versions are not locked.

## Historical preview

The earlier [setup-preview report](evidence/npm-audit-rea-6.7.0-preview-2026-10-18.json)
also reported zero findings. Its unarchived resolution was different (npm
metadata: 150 production, 32 optional, 181 total). It is historical evidence;
use the two committed locks and reports above for the current build scope.
The original REA archive matched registry SHA-512 metadata; signatures and
provenance were observed but not independently verified. See [initial findings](findings-2026-10-18.md).

## Repeat safely

Resolve/audit changes only in a separate reviewed Docker build environment.
For the committed trees, copy the relevant manifest/lock, use the same pinned
Node image and run `npm ci --ignore-scripts` with the image's optional policy,
then the corresponding audit command above. Preserve the raw JSON, date,
Node/npm versions, command and exact lock hash. Never enable runtime networking
to audit the analysis container or run `npm audit fix` automatically. Review
and verify any changed lock/image before analysis.

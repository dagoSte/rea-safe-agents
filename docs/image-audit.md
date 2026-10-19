# Whole-image inventory and vulnerability reports

The npm audit covers npm advisories. It does not establish the state of Debian
packages, bundled Java libraries, downloaded JDKs or native binaries.

`tools/scan_images.py` inventories both built images with a digest-pinned Trivy
0.76.0 container and emits full JSON vulnerability reports, CycloneDX SBOMs and
`provenance.json`. Its [release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.0)
and immutable image reference are pinned in the helper. The weekly version
check monitors new stable scanner releases; same-version scanner tag rebuilds
are outside its digest comparison scope.

## Run and interpret

Pull the exact `SCANNER_IMAGE` reference from the helper, then run:

```text
python3 tools/scan_images.py --context desktop-linux --output-dir /absolute/private-evidence/new-image-scan
```

The output directory must be new and outside the repository. The scanner has
no Docker socket and does not execute either target image's entrypoint. Docker
exports each inspected immutable image ID to an archive. Database download
containers have network access and no target archives; target parsing has
`network=none`, a read-only archive/cache, bounded memory/CPU/processes and
bounded temporary space. Reports are linked to the image ID, archive hash,
scanner digest and dated vulnerability-database hashes.

Docker stores can identify an image by its config, manifest or OCI index;
Trivy's report identifies its config. The helper verifies the exported
index/manifest/config chain and stored layer hashes before comparing that
config ID with the report. It accepts canonical USTAR outer headers only,
reads bounded JSON and never extracts or decompresses layers on the host.
Unsupported archive formats, ambiguous selection and case-insensitive JSON
key collisions fail closed. The last rule also conservatively rejects
case-distinct keys in data maps, such as labels.

On a Mac with strict Desktop sharing, the scanner's bind sources must also be
inside the allowed root. Use an exclusive disposable child of that root for
this optional audit's output/cache and archives, containing no control files,
logins or analysis reports. Move the evidence to private storage afterward and
remove that exact disposable audit workspace. Never re-enable broad shares to
make a scan work. The Linux CI job has no Desktop sharing layer.

An optional `--cache-dir /absolute/private-scanner-cache` reuses only a
dedicated database cache outside the repository. Dates and hashes are still
checked. Keep it exclusive to the scan; reuse alone does not establish that
two runs used identical databases. Compare the recorded hashes.

Exit 0 means **the reports were produced**, including all severities and
unfixed findings. It does not mean no vulnerabilities were found. Scanner
errors, malformed or empty inventory, image-identity mismatch and stale
databases fail the operation and preserve incomplete evidence. CI uploads
reports, SBOMs and provenance; database caches are excluded from artifacts.

This initial scan is report-only for CVEs. It has no hidden ignore list and
does not discard findings without a fix. Triage and release decisions must
review the actual findings; a successful CI scan is not a vulnerability-free
badge.

## Initial findings and triage

The first macOS ARM64 scan found advisories outside npm in both images.
Counts are scanner occurrences across packages and locations, not unique CVEs
or demonstrated exploit paths. Raw reports are retained; vendor triage is
recorded separately rather than altering the scanner output.

The 2026-10-19 ARM64 before/after comparison used byte-identical vulnerability
databases. Available Debian updates removed 13 occurrences per image (3
critical, 4 high, 6 medium), with none added:

| Final image | Critical | High | Medium | Low | Unknown |
| --- | ---: | ---: | ---: | ---: | ---: |
| REA | 3 | 67 | 105 | 91 | 1 |
| Agent | 2 | 74 | 149 | 124 | 1 |

These dated counts do not predict later builds or the Linux AMD64 CI results.
Raw reports include all findings, including vendor-triage items below.
The archived [provenance](evidence/image-scan-macos-arm64-2026-10-19.json)
records image IDs, report/SBOM hashes and database ages and hashes; the
[comparison](evidence/image-scan-comparison-macos-arm64-2026-10-19.json)
records the removed occurrences. Full local reports remain outside Git.

- Debian's Perl update `5.36.0-7+deb12u4` fixes reported advisories. Both final
  image builds now upgrade installed Debian packages before installing their
  dependencies. The reviewed Node, REA, client, Ghidra and JDK pins stay fixed.
  See [Debian DLA-4821-1](https://security-tracker.debian.org/tracker/DLA-4821-1).
- Trivy reports CVE-2023-45853 against zlib. Debian documents that the affected
  minizip code is not built into the relevant Bookworm binary packages; this
  is a source-to-binary applicability distinction, not a suppressed finding.
  See [Debian's record](https://security-tracker.debian.org/tracker/CVE-2023-45853).
- The agent image's SQLite CVE-2025-7458 remains a vendor-triage item; the
  Bookworm record does not establish an available security update. See
  [Debian's record](https://security-tracker.debian.org/tracker/CVE-2025-7458).
- Ghidra's bundled Netty and Bouncy Castle libraries have reported advisories.
  The Netty advisory requires a particular TLS server/mTLS configuration;
  Bouncy Castle's concerns PKIX name-constraint validation. Reachability from
  this project's headless analysis has not been demonstrated. That is not a
  blanket unaffected claim. Ghidra's bundled JARs are not replaced separately
  from its reviewed release. See the [Netty advisory](https://github.com/netty/netty/security/advisories/GHSA-c4c3-7fpv-j4q5)
  and [Bouncy Castle advisory](https://github.com/bcgit/bc-java/wiki/CVE%E2%80%902026%E2%80%908763).

## Coverage limits

The SBOM contains recognized components, not every file or embedded library.
Installed OS packages, npm metadata and supported Java archives receive the
scanner's matching. Offline Maven resolution, downloaded JDKs and arbitrary
native executables may not have sufficient metadata for matching. Declared
build pins provide context; they are not build attestations or independent
proof of those binaries' contents. See [Trivy archive scanning](https://trivy.dev/docs/latest/target/container_image/#tar-files)
and [Java coverage](https://trivy.dev/docs/latest/coverage/language/java/).

Containment controls still matter when an affected dependency cannot yet be
updated. Scanning and containment measure different properties, and neither
proves that a malicious package or unknown exploit is absent.

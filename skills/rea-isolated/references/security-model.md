# Security model

Reviewed baseline: 2026-10-18. The host OS, Python controller, native Docker CLI,
Docker daemon and relevant kernel/hypervisor remain trusted and maintained.
REA and the receiving client are separately contained processes.

## Enforced boundaries

Both containers are created stopped, pinned to local immutable image IDs and
inspected before execution. Both require non-root UID 1000, read-only roots,
`network=none`, dropped capabilities, no-new-privileges, active seccomp, private
namespaces, no devices/ports/Docker socket and bounded memory/swap/CPU/processes.
Bounded tmpfs holds fresh home/scratch state. Docker logging is disabled.

The agent has **zero host mounts**. It receives no API key, host login file,
SSH agent, Docker CLI or Docker configuration. The one credential inside it is
Claude's own subscription login, which the controller passes to the Claude Code
process (never to the container environment); Codex holds none. Its model/MCP relays bind only
inside its own isolated namespace. The controller transports bounded JSON/base64
frames over attached Docker stdin/stdout; no host network listener is needed
for live use. Offline tests use a localhost dummy provider and an inert login.

REA receives exactly one read-only mount containing private temporary copies
of manifest-approved bytes. The original input directory is never mounted.
The controller verifies path/size/SHA-256 before exposing any snapshot. Changed
bytes fail; added files are excluded. Symlinks, reparse points, hard links,
special files, traversal and oversized selections are refused. Selected files
may still contain secrets: review their content before approval.

Portable protected-path checks are defense in depth. Renamed bind mounts and
same-filesystem aliases defeat some path/mount detection methods. The retired
direct MCP entrypoint and empty-input diagnostics avoid mounting such original
trees. The paired analysis path copies only pinned bytes into a fresh private
staging tree. This removes continuing access to a mutable host directory; it
does not prove that the bytes chosen during configuration are nonsensitive.

## Three original risks and the added agent boundary

| Risk | Implemented control | Remaining limit |
| --- | --- | --- |
| Sensitive host data exposure | No home/credential/socket mounts; only frozen approved file bytes enter REA; no input mount enters the agent | Selected bytes can return through MCP/model data; private logs and deliberate exports can disclose them |
| Malicious instructions cause host actions | Separate contained agent, removed host tools, 27 allowlisted MCP tools enforced on calls, reverse callbacks blocked | Results may mislead analysis; moving them into a privileged agent changes the trust boundary |
| Compromised npm/REA or agent code escapes restrictions | Separate non-root containers, no network/socket/capabilities, inspected settings, readonly roots and bounded resources | Unknown Docker/kernel/hypervisor defects and compromised trusted host software can defeat isolation |

A compromised package cannot simply call the host shell or read arbitrary host
files through the provided interface. It could attack the runtime or broker,
read approved input, falsify results, exhaust its bounded resources or try to
consume the permitted model budget. The same shared runtime/kernel is not two
independent protection layers. A separate VM or machine adds another boundary
for higher-assurance deployments; no extra VM is installed by this project.

## Trusted protocol broker

The broker accepts only the approved MCP lifecycle and 27 static-analysis
tools. It checks actual calls, target paths and close arguments; only the target
tools (`open_binary`, `analyze_javascript_application` and the five Android
queries) name a path, always a file in the frozen `/input` snapshot, `open_binary` accepts only the Ghidra provider, and snapshot
import/export is refused. Each result is relayed
as one text copy of at most 200,000 bytes, cut visibly in the middle when larger.
Initialization
removes reverse capabilities; sampling, roots, elicitation and server-to-host
requests are unavailable. Optional discovery gets a local MethodNotFound.

Model requests go only to a fixed Anthropic Messages/token count endpoint or
the ChatGPT Codex Responses endpoint over verified TLS. Arbitrary
hosts/paths/queries, redirects, ambient proxies and hosted model tools are
rejected. Claude's subscription login is accepted only in its expected
`Bearer` form and forwarded unchanged; the dedicated ChatGPT login stays in the
controller, which adds it to Codex requests and refreshes it there. The
selected explicit model and Claude's output cap are applied by the controller,
not accepted from contained code. Strict field,
beta and text/tool-history allowlists also reject provider-side MCP connectors,
cloud skills/containers, file/media references and prior conversation handles.
A harmless tool catalog cannot authorize an integration through another field.

This intentionally permits data egress to the selected model provider. It is
not a confidentiality boundary between approved inputs and that provider, and
not a usage budget: allowed calls consume the subscription's usage limits.
Use a login dedicated to this work where the service allows it, and revoke it
from the account settings if it leaks. Do not put additional secrets in prompts.

The parser requires UTF-8, rejects duplicate keys/non-finite numbers, and limits
JSON depth/items before allocating nested structures. Transport queues, frames,
MCP pending calls, payloads, transcripts, API requests/responses and elapsed
time are bounded. Containers are removed by exact IDs, including on failure;
auto-removal races are accepted only after successful confirmation of absence.
No parser or application-level filter substitutes for the Docker boundary.

## Build and supply chain

Build-time network access is separate from runtime. The supplied context
allowlists contain only reviewed Dockerfiles, helper code and npm manifests.
Never add build secrets, host mounts, SSH forwarding, privileged entitlements
or the Docker socket. The official Node image index and direct package versions
are pinned; both images use committed transitive integrity locks and
`npm ci --ignore-scripts`. REA omits optional npm providers; client native
packages are linked without running their postinstall hooks. The REA image adds
Ghidra 12.1.4, Temurin JDK 21.0.12.1 and the jadx-headless-mcp 0.7.1 JAR (the
JADX bridge REA audited, Apache-2.0), each verified against a pinned SHA-256.
JADX parses an untrusted APK inside the same container, limits and network
denial; a parser defect there is contained like one in Ghidra.
On arm64 the decompiler and GNU demangler are compiled from that same verified
archive, because the release ships x86_64 natives only. Ghidra runs inside the
REA container under the same limits, with a 1 GiB heap (2 GiB on the large
profile) and no network. The
arm64 natives are compiled with Debian bookworm's GCC 12 (`g++` and `make`
pinned), whose point releases follow Debian security updates. Ghidra projects
live in REA's bounded tmpfs. The standard profile analyzes binaries of a few
megabytes; the large profile (5 GiB, 4 CPUs, 256 processes, 2 GiB `/tmp`, a
2 GiB Ghidra heap, a 1,740-second first analysis and a 1,800-second client
tool timeout) is required above 8 MB,
and runs refuse such files on the standard profile. Its limits and settings
are inspected exactly like the standard ones, and the agent container keeps
the standard limits.

Lifecycle suppression prevents that install hook path; malicious library/native
code can still execute later inside the containers. npm integrity establishes
consistency with the committed lock, not publisher trust. The dated audit JSON
reports known npm advisories, not malware or OS image vulnerabilities. OS apt
packages are not locked, so these builds are not claimed byte-reproducible.
Independent provenance/attestation verification and an image-wide vulnerability
scan were not completed. See [npm evidence](https://github.com/dagoSte/rea-safe-agents/blob/main/docs/npm-audit.md).

## Compatibility and maintenance

The current supported scope is Linux and macOS (POSIX), using Linux containers.
Linux requires local Docker Engine/Desktop; macOS requires maintained Docker
Desktop. Windows support is experimental: native policy/profile tests passed, while
Docker Desktop integration remains unverified. Remote daemons, native Windows containers and alternate engines
are not supported. Rootless/cgroup variations must pass all the same checks.

The conservative floors are Desktop 4.95.0 and Engine 29.8.2. These are dated
reviewed versions, not an evergreen vulnerability guarantee. Recheck official
advisories before installation and upgrades. The motivating Desktop 4.41.2
installation preceded the CVE-2025-9074 fix, which demonstrated that omitting
a socket mount alone does not protect an affected runtime.

Arguments use `shell=False` and CSV mount fields. Windows accepts only the exact
native local-drive translation inspected by Docker Desktop; unknown UNC/WSL
aliases fail. Native Windows profile protection uses the process token's account
profile, not just caller-controlled USERPROFILE. That test must pass natively.
Mappings and mocks do not establish native Docker integration on another OS.

The profile supports offline/static analysis, including native executables
through Ghidra. Internet, browser/device access, native desktop apps, debuggers
and other providers require a separate reviewed design. A failed runtime, test, inspection or handshake never authorizes host
execution, broader sharing, weaker limits or an unreviewed version.

## Sources

- [Docker Engine security](https://docs.docker.com/engine/security/)
- [Docker security announcements](https://docs.docker.com/security/security-announcements/)
- [Docker container options](https://docs.docker.com/engine/containers/run/)
- [Python mount-detection limits](https://docs.python.org/3/library/os.path.html#os.path.ismount)
- [Windows account profile API](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getuserprofiledirectoryw)
- [Codex configuration](https://learn.chatgpt.com/docs/config-file/config-reference)
- [Claude Code CLI](https://code.claude.com/docs/en/cli-reference)
- [REA security policy](https://github.com/morluto/rea/blob/main/SECURITY.md)

# Validation record

Last updated: 2026-10-19. Live analyses used the owner's own Claude and ChatGPT subscriptions on macOS ARM64.

## 2026-10-19 increment: native analysis, bounded results, subscription logins

This increment adds Ghidra 12.1.4 to the REA image, exposes 16 read-only native
queries, bounds every relayed result at 200,000 bytes and replaces API keys with
subscription logins. Native macOS ARM64 was verified locally and native Linux
AMD64 in [public CI run 39233416497](https://github.com/dagoSte/rea-safe-agents/actions/runs/39233416497),
which passed all four jobs. The matrix in the last section describes the previous release.

| Check | Result |
| --- | --- |
| Policy suite, native macOS | 71 tests: 70 passed, 1 skipped (Windows-only profile lookup) |
| `rea doctor --provider ghidra` under the REA container limits | Healthy: Ghidra 12.1.4, JDK 21.0.12.1, decompiler built for linux/arm64 |
| `verify_runtime.py`, both clients, native macOS ARM64 | Passed: ZIP inventory with known child SHA-256, then Ghidra recovered the known string from a generated ELF; eleven probes and cleanup passed |
| Claude subscription profile offline | Passed: non-bare Claude Code sent `Authorization: Bearer` with `oauth-2025-04-20`; the gateway checked it against the inert login. The fixture receives no credential, so the live header-building branch is covered by unit tests only |
| Real analysis with an outside agent as the model | Passed for Claude Code: decompiled `main` and `fnv1a32` of a compiled x86-64 ELF and decoded its XOR-0x5a string from REA output alone |
| Public CI, this release | All four jobs passed: Linux, macOS and Windows policy suites, and Linux AMD64 runtime with both real clients; Ghidra recovered the known ELF string |
| Live Claude subscription analysis, native macOS ARM64 | Passed: `claude-opus-5-5` through the owner's `claude setup-token` login, 7 model requests and 11 successful REA calls; the report matched the known source (see below) |
| Live Codex analysis with a ChatGPT login, native macOS ARM64 | Passed: `gpt-6.1-sol` through a dedicated `codex-login` device login, 5 model requests and 9 successful REA calls; the report matched the known source. The first live attempts found that `gpt-5.5` is not offered to ChatGPT accounts and that real responses carry two fields the profile then lacked (`phase`, `logprobs`); both are now admitted as bounded data |

The live Claude run analyzed a benign x86-64 ELF compiled for the test, whose
source the testers knew. The contained Claude Code opened it, read the overview,
procedures and strings, decompiled `main` and `fnv1a32`, read the encoded bytes,
followed their references and closed it. Its report identified the FNV-1a hash
and its constants, the usage banner, the libc-only imports and the XOR-0x5a
string `benign-marker-7731`, and noted that Ghidra's string list started that
string one byte late. The [sanitized record](evidence/live-claude-subscription-macos-arm64-2026-10-19.json)
keeps the model, versions, calls, probes and outcome, without paths or the login.
The live Codex run reached the same findings from the same binary; its
[record](evidence/live-codex-chatgpt-macos-arm64-2026-10-19.json) is sanitized the same way.

The [macOS report](evidence/runtime-macos-arm64-ghidra-2026-10-19.json) records
image IDs, client versions, REA call order and all probes. The outside-agent
run used the unchanged controller, tunnel and gateway policy with a localhost
relay in place of the model; its model turns were written by another agent
session. It shows that the tools are usable for real analysis, not provider
connectivity. Before this increment, the same kind of run had shown that the
contained model could not read native strings or code, and that Claude moved a
54 KB result into a file the model could not open.

## Earlier record (previous release)

The repository history was squashed into a single commit on 2026-10-19. The
commit named below belonged to the earlier history; its CI run stays public.

The repository is public. [All four jobs passed](https://github.com/dagoSte/rea-safe-agents/actions/runs/39140058024)
on implementation commit `54c926c8d513e4e29b12051bede44dda7fbc7042`. The
[archived CI summary](evidence/ci-public-2026-10-18.json) records exact counts,
job URLs and the dedicated Windows account-profile result.

| Layer | Linux host | macOS host | Windows host |
| --- | --- | --- | --- |
| Native Python policy tests, 64 total | 62 passed, 2 skipped | 63 passed, 1 skipped | 62 passed, 2 skipped |
| Dedicated Windows account-profile test | Not applicable | Not applicable | **1 passed, 0 skipped** |
| Native Docker restrictions and contained-agent probes | Passed: Engine 29.8.2, AMD64 | Passed: Desktop 4.95.0 / Engine 29.8.2, ARM64 | Not verified |
| Both real clients through actual REA analysis | Passed: Codex and Claude | Passed: Codex and Claude | Not verified |

Windows remains **Experimental** until full native Docker Desktop integration
passes. Native Python policy checks alone do not establish that runtime layer.

## Current paired-container evidence

The maintained `tests/verify_runtime.py` completed on native macOS ARM64 and
native GitHub-hosted Linux AMD64 using lockfile-built images. Sanitized results
are archived for [macOS](evidence/runtime-macos-arm64-2026-10-18.json) and
[Linux](evidence/runtime-linux-amd64-2026-10-18.json). Each report contains exact
local image IDs, client versions, actual REA call order, known child SHA-256
and all eleven agent probes. Image IDs identify those builds, not registry
references or a reproducible-image promise.

For **each client**, the test first required a successful real `binary_session`
call and explicit client rejection of undeclared tools: Codex `exec_command` /
`apply_patch`, Claude `Bash` / `Write`. Then the real contained client dispatched
`open_binary → inspect_artifact → close_binary` against real contained REA.
All three results succeeded and the returned inventory included the independently
known SHA-256 `56c40b1a1ff2e0f1fd33517798751713cb57fc6745b29600f48ea9ac12363c11`
for `fixture-only.txt`. Each analysis used four local dummy-model requests.

The eleven agent checks passed: non-root, no-new-privileges, zero effective
capabilities, seccomp active, no active non-loopback interface, no Docker CLI,
no Docker socket, no host input mount, no model credentials, root writes denied
and outbound network denied. Docker inspection independently required zero
agent mounts and `network=none` for both containers. Both exact containers and
fixture inputs were removed; no managed containers remained after testing.

These checks use real binaries and the actual controller/transport, with a
deterministic localhost model fixture. They establish dispatch and isolation
behavior, not the reasoning quality of a real model or paid-provider connectivity.
At that commit the gateway's real HTTPS request construction was covered by
policy tests only; live subscription analyses were first run in the 2026-10-19
increment above.

## Policy suite and independent review

The suite covers unsafe container settings, create-before-start refusal,
cleanup on interrupt/error, non-reading pipe deadlines, exact image/mount/namespace checks, redirected
HOME/USERPROFILE, Windows path mapping, prompt option injection, frozen-input
hash/link/reparse/size restrictions, fixed gateway endpoints, hosted-tool
rejection, stale receipts and UTF-8 framing with allocation limits.

Independent review found and retested fixes for private output path aliases,
installed-skill/worktree repository detection, AutoRemove cleanup races,
UTF-16 parser-budget bypass, Claude discovery/token-count compatibility and
Codex's real MCP per-tool approval requirements. A provider-side MCP connector
bypass through the Messages body was reproduced with mocked HTTPS, then closed
with request-field/beta/content allowlists and zero-connect regression tests. Each issue was fixed without
grants to a host tool, broader runtime networking or Docker socket access.
The old direct-host MCP path is retired; diagnostics mount empty temporary
inputs. Original selected trees are never mounted by the current public flow.

The final local suite contains 64 tests. Native macOS passed 63, with the one
Windows-only profile lookup correctly skipped. Linux ARM64 Python-in-Docker
passed 62, with Windows lookup and case-insensitive-filesystem tests skipped.
That Linux result covers Python behavior, not a native Linux host's Docker
integration. The skill's frontmatter passed the Codex skill validator. Hosted
results are recorded in the matrix and archived CI summary above.

## Cross-platform requirements

`checks.yml` runs native Ubuntu/macOS/Windows policy tests. The Windows job
separately requires the account-profile test to run and pass without skipping. The Linux integration job
pins an official Docker setup action and Engine generation, builds both images
and runs the real two-client ZIP test. All actions use immutable commits; no
model-provider secrets are used.

The earlier [private-repository run](https://github.com/dagoSte/rea-safe-agents/actions/runs/39138923109)
could not start any runner steps because GitHub reported account payment or
spending limits. After the authorized visibility change to public, the new
standard hosted run executed and passed. Account billing settings were unchanged.

Skip scope in the successful policy matrix:

- Linux: native Windows profile lookup and case-insensitive filesystem alias test.
- macOS: native Windows profile lookup.
- Windows: Unix account database test and the legacy console interrupt fixture.
  The **Windows account-profile test was not skipped**; it passed in the full
  suite and again as the mandatory dedicated check.

Windows Docker Desktop testing still needs a suitable native host; see the
[experimental guide](../skills/rea-isolated/references/windows-experimental.md).
No native Windows Docker runtime result is claimed. Public Windows policy CI
must not be presented as verification of Linux-container mounts or runtime
isolation on Windows.

## Earlier deployment evidence

Before the paired layer, the original REA image passed 14 fixed container probes,
version 6.7.0 and a setup preview with zero applied actions. Real MCP discovery
advertised 207 tools (largest JSON message 3,158,403 bytes). A standalone real ZIP
analysis also passed. These are historical results; direct host MCP and host
receiving sessions are now retired.

Native `inspect_plist` required macOS utilities unavailable in the Linux image;
REA returned `capability_unavailable`. No host utility was invoked. An unshared
`/Applications` mount was refused; tests used a narrow `/private/tmp` selection
without expanding Docker sharing. The paired profile deliberately exposes only
six tools and makes no claim that every upstream provider is available.

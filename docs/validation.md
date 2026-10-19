# Validation record

Last updated: 2026-10-19. Live analyses used the owner's own Claude and ChatGPT subscriptions on macOS ARM64.

## 2026-10-19 increment: independent-review fixes

Applied above Android commit `a8d5f41`. Exact native release, architecture and
tarball checks now include orphaned lock entries; Python pin extraction is
scoped to module constants and the required REA equality. The controller
parses complete SSE events, handles malformed/deep JSON, and associates a
Codex provider-final label with the exported visible text's SHA-256. Effective
targets constrain both the snapshot and file tool calls; large-file guidance
is checked against the final prompt limit before login or container startup.

| Check | Result |
| --- | --- |
| Full policy suite, native macOS ARM64 | 143 tests on each of Python 3.11.5, 3.12.8, 3.13.2 and 3.14.7: 142 passed, 1 Windows-only profile lookup skipped |
| Version-check regressions | 21 tests passed; new counterexamples failed before their fixes |
| Report and resource boundaries | Non-author re-read and targeted probes passed, including multiline SSE, CR/LF/CRLF split across chunks, deep JSON on Python 3.11, persisted answer hashes, target filtering and oversized augmented prompts |
| Runtime verifier | Updated to retain scoped broker guards and check the provider answer hash against the real client's transcript; this revised runtime check has not yet been run |

The preceding Android baseline passed all four jobs in
[CI run 39256339684](https://github.com/dagoSte/rea-safe-agents/actions/runs/39256339684),
including Windows policy/profile checks and Linux runtime analysis with JADX
and both clients. That run predates these review fixes and does not establish
their Linux, Windows or Docker runtime coverage. No paid model call was made
for the review fixes.

## 2026-10-19 increment: Android apps

JADX through jadx-headless-mcp 0.7.1 (SHA-256 `6e5eacf5…`, the JAR REA 6.7.0
audited; REA reported its source revision `5844800a` only for this file).
Native macOS ARM64, standard profile unless stated.

| Check | Result |
| --- | --- |
| `rea doctor --provider jadx` under the container limits | Healthy: bridge JAR validated, full JDK 21 with `jdk.compiler` |
| Generated 1.6 KB APK (binary manifest and one DEX class) | All five queries passed: package `fixture.rea`, version 1.0, SDK 21/34, permission `INTERNET`, and the decompiled `marker()` returning the known string; peak 486 MiB |
| F-Droid client 2.0.2, 12.5 MB, three DEX files, 11,960 classes | Package summary 9 s, class search 0.7 s, class 0.9 s, references 9.6 s; peak 1,178 MiB and 53 MiB of `/tmp`. A missing method was refused with the list of available ones |
| `verify_runtime.py`, both clients | Passed: Codex (standard profile) and Claude (large profile) recovered the generated APK's package, permission and decompiled method through the audited bridge |
| Live Claude subscription analysis with `--template android` | Passed: `claude-opus-5-5` analyzed the F-Droid client in 19 model requests and 39 successful REA calls (17 class searches, 7 decompiled methods, 6 classes, 2 reference traces). The report identified `org.fdroid.fdroid` 2.0.2, mapped each permission to an app-store or nearby-swap feature, found no SMS, contacts, accessibility or device-admin use, rated it low risk and stated that the signature was not verified |

## 2026-10-19 increment: large binaries

One REA session per binary, through the production controller and container
policy on native macOS ARM64 (Docker Desktop: 8 CPUs, 7.75 GiB). Calls:
`open_binary`, `binary_overview`, `list_strings`, `list_procedures`,
`search_strings`, `close_binary`. Peaks were sampled every 1.5 s.

| Binary | Profile | First analysis | Peak memory | Peak `/tmp` | Result |
| --- | --- | --- | --- | --- | --- |
| 16 KB ELF fixture | standard | 12 s | 792 MiB | 12 MiB | All calls passed |
| 3.8 MB ELF (`decompile`) | standard | 116 s | 1,268 MiB | 118 MiB | All calls passed |
| 25 MB `libjvm.so` | standard | failed after 33 s | 1,464 MiB | 256 MiB (full) | `execution_failure`: the tmpfs was full |
| 25 MB `libjvm.so` | 4 GiB, 2 GiB `/tmp`, REA's 330 s default | timed out at 330 s | 3,172 MiB | 388 MiB | `provider_timeout` |
| 25 MB `libjvm.so` | large | 830 s | 3,952 MiB | 542 MiB | Overview and search passed; full string and procedure listings exceed REA's stdio response limit (`resource_constraint`) |

The large profile therefore allows 1,740 s for the first analysis, about
twice the measured time, and the clients 1,800 s per REA call. The runtime
check runs Claude against the large profile and Codex against the standard one;
both passed locally and in public CI.

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
| Live two-file `triage` template with Claude, native macOS ARM64 | Passed: `claude-opus-5-5` analyzed an archive and an ELF one at a time (12 successful REA calls, 9 model requests) and wrote `report.md` with a risk level per file and a summary; it reported that REA lists archive entries but cannot read the script inside |
| Live Codex analysis with a ChatGPT login, native macOS ARM64 | Passed: `gpt-6.1-sol` through a dedicated `codex-login` device login, 5 model requests and 9 successful REA calls; the report matched the known source. The first live attempts found that `gpt-5.5` is not offered to ChatGPT accounts and that real responses carry two fields the profile then lacked (`phase`, `logprobs`); both are now admitted as bounded data |

An independent three-reviewer audit of the release (commit `4ee3dc0`) confirmed
three defects, all fixed afterwards and re-checked by a non-author verifier with
mutation tests: a malformed Codex access token could be printed in an error
message (tokens must now be header-safe, and rejected headers are reported
without their value); verifying one configuration could delete another whose
name looked like its receipt (names are now `<name>.json`, receipt-like names
are refused in any case, and only a real receipt is ever replaced); and the
short Codex example lacked `--codex-login`. The audit also reproduced the
intermittent Windows snapshot error fixed in `de1b335`.

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

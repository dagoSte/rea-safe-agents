# Contained receiving agents

Both the REA server and its receiving client run in separate inspected Docker
containers. Host Codex/Claude installations and their credentials are unused.
The public host-session entrypoints are retired. `agent_session.py` retains the
reviewed profile library for the contained worker and regression tests.

## Reviewed clients

| Client | Linux version pinned in the agent image | Effective actionable tools |
| --- | --- | --- |
| Codex | CLI 0.163.0 | The 22 `mcp__rea` tools; passive MCP resource/question helpers may also appear |
| Claude Code | 2.1.302 | The same 22 `mcp__rea__*` tools in initialization and model requests |

The REA tools are `open_binary`, `binary_session`, `inspect_artifact`,
`inspect_analysis_view`, `analyze_javascript_application` and `close_binary`,
plus 16 read-only Ghidra queries of the open target: `binary_overview`,
`list_segments`, `inspect_native_load_image`, `list_strings`, `search_strings`,
`list_procedures`, `search_procedures`, `procedure_info`, `procedure_pseudo_code`,
`procedure_assembly`, `procedure_callees`, `procedure_callers`, `xrefs`,
`list_names`, `read_bytes` and `analyze_function`. Annotation tools and all other
upstream tools are hidden and calls to them are rejected. Catalog
filtering alone is not the authorization check. Reverse server requests and
resource/prompt methods are blocked by the broker; optional `server/discover`
is answered locally with MethodNotFound. Tool targets must use frozen `/input`
paths. No other tool opens a filesystem path; `inspect_analysis_view` can echo
paths inside inline evidence, which REA does not reopen. `open_binary` accepts
only the Ghidra provider and no snapshot import, and `close_binary` accepts no
export arguments.

Every tool result reaches the model as one text copy. The broker drops the
duplicate structured result and the tools' output schemas, and cuts any text
above 200,000 bytes in the middle with an explicit note asking for a narrower
view. It announces that size to Claude (`anthropic/maxResultSizeChars`), which
otherwise saves results above 50,000 characters to a file the contained model
cannot read. Codex receives a matching per-tool `output_token_limit`, which
otherwise cuts results near 12,000 bytes. A REA call may run for 15 minutes in
both clients, because the first native query starts Ghidra. JSON-RPC errors are
bounded the same way, and non-text blocks become a short note.

REA's list tools (`list_strings`, `list_procedures`, `list_names`) take no offset
or limit. Ghidra's lists for a binary of a few megabytes already exceed 200,000
bytes, and REA itself refuses results above its 10 MiB budget. For larger
binaries, use `search_strings`, `search_procedures` or one address or procedure.

Codex disables shell, editing, browser/computer, image, apps, hooks, plugins,
delegation and code-execution features. Its global approval policy is `never`.
Only the allowlisted contained MCP operations receive explicit per-tool
`approval_mode="approve"`; otherwise this client discovers REA but refuses real
calls. No host command receives an approval bypass.

Claude runs without bare mode, which ignores subscription logins, but with
`--tools ""`, strict MCP configuration, empty settings sources, `dontAsk`, no
hooks/Chrome/slash commands or persistent session. The
sole allowed MCP namespace is the broker's 22-tool catalog. Built-in plugin
metadata or agent type names are not evidence of callable tools. The image
and client code remain untrusted contained processes for host access purposes.

Every client starts in a fresh tmpfs home/workdir. The agent container has no
host mount, Docker executable/socket, credential in its environment, active
external interface or external network route. Claude's own subscription login
is the one exception, held only by the Claude Code process (see below). Each launch inspects the stopped container and requires
eleven worker checks. Both clients and REA have separate resource bounds.

## Configure, verify and run

From the skill directory, after building both images and pinning REA:

```text
python3 scripts/agent_container.py configure --rea-config /absolute/private-control/rea.json --image rea-agent-local:codex-0.163.0-claude-2.1.302-locked --client codex --output /absolute/private-control/codex.json
python3 scripts/agent_container.py verify --config /absolute/private-control/codex.json
python3 scripts/agent_container.py run --config /absolute/private-control/codex.json --model EXPLICIT_MODEL_ID --prompt-file /absolute/private-control/prompt.txt --output /absolute/private-control/new-analysis
```

Change `--client` and the private config path for Claude. Current support is
Linux/macOS (POSIX); Windows support is experimental. Keep control/output directories private,
outside the input selection, Git and web server document roots. Global client
configuration is unchanged. See the [experimental Windows guide](windows-experimental.md)
for future validation requirements.

Configuration records both image identities, helpers, REA deployment and the
selected file manifest. Changed approved bytes fail before startup; newly added
files are excluded. A configuration or helper change invalidates the receipt.
Receipts are bound to the native host OS; moving one cannot authorize another OS.

Offline verification uses the real clients and REA through the actual broker.
The localhost dummy model first forces undeclared shell/write requests, then
calls real `binary_session`. Success requires explicit tool rejection, a
successful MCP result, the expected tool catalog, all worker probes and cleanup.
A separate maintained integration test opens an inert ZIP, inspects real REA
inventory and checks the independently known child SHA-256. It then opens a
generated minimal ELF and requires Ghidra to recover its known string, for both
clients. Neither test makes a real provider request.

## Model gateway

Each client uses its owner's own subscription; API keys are not supported.
The agent reaches the controller through a loopback URL inside its isolated
namespace. A bounded framed channel over Docker stdin/stdout relays model data;
no host port or Docker socket is exposed to the agent.

| Client | Login | Fixed HTTPS destination and allowed POST paths |
| --- | --- | --- |
| Claude | Your `claude setup-token` login, held by the contained Claude Code | `api.anthropic.com:443`, `/v1/messages`, `/v1/messages/count_tokens` |
| Codex | A dedicated ChatGPT login, held by the controller | `chatgpt.com:443`, `/backend-api/codex/responses` |

**Claude.** The controller reads your login from `CLAUDE_CODE_OAUTH_TOKEN`,
keeps it in memory for the run and never writes it to disk. It passes it to the
unmodified Claude Code, which signs in with it. For each request the gateway
checks that the client's `Authorization` header carries exactly that login, then
sends its own HTTPS request to `api.anthropic.com` with that header value,
`anthropic-version` and the client's beta values plus the OAuth capability. It
replaces the model ID and caps `max_tokens`; the system prompt, messages and
tools pass unchanged. Other client headers, such as the user agent, are not
forwarded, which Anthropic's gateway guide permits. Unlike that guide's advice,
beta values are an allowlist: an unknown value stops the run rather than reach
Anthropic, because beta features can enable provider-side integrations.

The gateway never authenticates with a login of its own. Anthropic's terms
allow signing in to the unmodified Claude Code with your own subscription,
including through a gateway, and forbid tools that collect, store or
intermediate Claude.ai credentials. Whether a local gateway that checks and
re-sends your own login counts as intermediating is for Anthropic to judge;
this profile keeps the login with you and your client and stores it nowhere.

**Codex.** `agent_container.py codex-login` signs in through OpenAI's device
flow in a one-off container that has network access but no input, REA, host
mount or Docker socket. The resulting login file is private to the controller:
mode 0600 on Linux and macOS; on Windows, the private control directory's ACL
protects it. It is never shared with a host Codex install, because refresh
tokens are single-use. The controller refreshes it at `auth.openai.com` before expiry or
after a 401, writes each rotated token back atomically before use and lets one
run hold it at a time; after three refreshes in one run it stops. If the file
cannot be replaced, the new login stays in `<file>.tmp` and the error names it.
The contained Codex sends no credential; the gateway adds the access token and
account ID, plus Codex's own identification (`originator: codex_exec`, its user
agent and version), because the requests come from the contained Codex CLI. Its
endpoint is the one the Codex CLI uses with a ChatGPT login, not a documented
public API, so it may change. OpenAI recommends API keys for automated
workflows; using a ChatGPT login here is the owner's choice.

Claude may append the exact query `beta=true`. Other paths, URLs, queries and
redirects fail. TLS certificates are verified; ambient proxies are ignored.
The controller fixes the model ID, rejects hosted model tools, caps Claude
output at 32,000 tokens and bounds requests, responses and total duration: one
streamed answer may take 15 minutes and a session 30. The ChatGPT backend
accepts no output cap, so `max_output_tokens` and `background` are removed and
only byte and time budgets bound Codex responses. Retry and plan-usage headers
(`retry-after`, `x-should-retry`, `anthropic-ratelimit-unified-*`) return to the
client, so it can tell a usage limit from an outage.
Token counting uses its own request shape and the same destination/budgets.
Top-level fields, tool declarations, beta identifiers and text/tool-history
content types are allowlisted for the pinned clients. Provider-side MCP
connectors, cloud skills/containers, cloud-file/media references and prior
conversation handles are refused, including on token-count requests. Model
images/documents and unreviewed client features are outside this profile.

The gateway is a controlled egress channel, not offline model inference.
Analysis data can reach that provider. A compromised contained process can
submit data or consume the subscription's usage within the request budget. A
compromised Claude process can also read its own login; its only egress is the
gateway to `api.anthropic.com` and the private transcripts. Revoke a leaked
login from your Claude or ChatGPT account settings. Both subscription paths
completed a live analysis on macOS ARM64; see the validation record.

Raw transcripts are saved as private files and are not executed or rendered as
host instructions. Treat terminal escapes, links and embedded instructions as
untrusted. A later privileged chat consuming them has a different boundary.

## Official references

- [Codex configuration](https://learn.chatgpt.com/docs/config-file/config-reference)
- [Claude Code CLI](https://code.claude.com/docs/en/cli-reference)
- [Claude Code gateway configuration](https://code.claude.com/docs/en/llm-gateway)
- [Claude token-count endpoint](https://platform.claude.com/docs/en/api/messages/count_tokens)

The exact pinned-client behavior and real dispatch tests are the evidence used
here. Configuration documentation alone does not establish runtime containment.

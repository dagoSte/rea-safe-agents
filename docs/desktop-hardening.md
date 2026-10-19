# Docker Desktop sharing and dedicated staging

The container mount policy and the Desktop VM's access to the host are
different boundaries. REA receives one frozen-input mount and the agent has
zero host mounts. Desktop may nevertheless share much larger host directories
with its VM. A sufficiently powerful container/VM/daemon compromise can expose
that larger surface. A container with the intended mounts has no ordinary
access to all Desktop shares.

Docker documents the default virtual shares as `/Users`, `/Volumes`,
`/private`, `/tmp` and `/var/folders`. Its optional Enhanced Container
Isolation setting requires a Business subscription. ECI is not required by
the saved-sharing check below and its setting is not execution evidence.
See [Desktop settings](https://docs.docker.com/desktop/settings-and-maintenance/settings/)
and [platform security](https://docs.docker.com/faqs/platform/).

## Inspect first

```text
python3 skills/rea-isolated/scripts/desktop_policy.py
```

The command reports only a policy projection: virtual sharing directories and
ECI's boolean setting. It does not change Desktop or print unrelated settings.
It reads the operating system's account home, not a replacement `$HOME`.
Missing, malformed or conflicting saved settings are reported as unknown.

On the reviewed Mac, the five default broad roots were present and ECI was
false. That is a saved-configuration observation, not an executed escape test.

## Prepare one dedicated root on macOS

Create an empty, persistent directory private to your account, outside the
repository, webroots, inputs and control/login/output directories. For example:

```sh
mkdir -m 700 "/Users/Shared/rea-safe-staging-$(id -u)"
```

That directory is for disposable frozen copies and empty diagnostics only.
Never store logins, control configurations, reports or other projects there.
Concurrent runs create separate temporary children and remove them afterward.

Before changing Desktop, review which other projects depend on its existing
shares. In Desktop Settings > Resources > File sharing, replace broad shares
with only the canonical staging directory. Apply the change and restart
Desktop when other workloads may be interrupted. Review synchronized shares
and other sharing mechanisms separately; the checker does not inspect them.
This project does not edit global settings or restart Desktop for you.

## Pin and enforce the saved policy

Use the actual canonical directory, replacing the example account ID below:

```text
python3 skills/rea-isolated/scripts/desktop_policy.py --staging-root /Users/Shared/rea-safe-staging-501 --strict
python3 skills/rea-isolated/scripts/container.py configure --image rea-local:6.7.0-ghidra-12.1.4-locked --context desktop-linux --input-dir /absolute/selected-input --staging-root /Users/Shared/rea-safe-staging-501 --desktop-share-policy strict --output /absolute/private-control/rea.json
```

Pair and verify again after changing deployment settings or helpers. Both
analysis and diagnostics use the configured staging root; original input
directories do not need to be shared with Desktop. Control and login files
must stay outside staging, including paths that have not been created yet.

`strict` checks the saved virtual-share list on every launch, before container
creation. Only the single canonical staging root satisfies it. Broad, extra,
unknown or conflicting saved shares refuse the launch. If the legacy and
current settings files disagree, resolve which configuration is authoritative
and preserve a private backup; the checker does not silently choose one.

The result is named `saved-share-policy-satisfied` and always contains
`effective_vm_verified: false`. The saved file may differ from an active VM;
the result is not VM attestation, a hypervisor guarantee, or proof that other
sharing mechanisms are disabled.

## Platform scope and compatibility

Existing deployments without these fields retain OS-temp staging and
diagnostic reporting. Set `staging_root` and `desktop_share_policy: strict`
explicitly for this narrower saved-settings policy. Existing receipts do not
replace the fresh preflight check.

| Runtime | Sharing policy |
| --- | --- |
| macOS Docker Desktop | Saved virtual-share inspection and strict gate supported |
| Native Linux Engine | Desktop sharing policy not applicable; the host kernel remains trusted |
| Docker Desktop on Linux or Windows | Diagnostic result is unsupported; strict refuses rather than inferring macOS assurance |
| Windows WSL2 | Drive automount, integration and manually mounted paths require a separate assessment |

Windows custom-directory privacy also depends on account-specific ACLs;
POSIX mode bits do not establish them. Full native Windows Docker integration
remains experimental. A dedicated VM or machine containing the controller,
Docker and both containers is a separate deployment option; this check does
not create one.

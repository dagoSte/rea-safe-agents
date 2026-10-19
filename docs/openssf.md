# OpenSSF assessments

These two public assessments describe repository practices. They do not certify
that the gateway is free of defects or that a container cannot escape.

## Scorecard

- [Public result](https://scorecard.dev/viewer/?uri=github.com/dagoSte/rea-safe-agents)
- [Workflow](../.github/workflows/scorecard.yml)
- [First successful run](https://github.com/dagoSte/rea-safe-agents/actions/runs/39291507521)

The first assessment of `03cdb5737ce7ccc09fb79b64b1799fcd6f346dcb`, on
2026-10-19, scored **5.0/10**. The badge is live and can change after later runs.
It gave full scores to license, security policy, workflow token permissions,
dangerous-workflow checks and pinned dependencies. It found no SAST integration,
branch protection or approved pull-request changesets. Repository age, contributor
diversity and missing release history also affect the assessment. Some checks
are unavailable when no applicable pull requests or releases exist.

Its vulnerability check reported zero findings in its own scope. This does
**not** supersede the nonzero OS/Java findings in the
[whole-image audit](image-audit.md). The custom weekly pin checker is also not
recognized as a dependency-update bot, and deterministic generated tests are
not recognized as an integrated fuzzing service.

The action runs only on `main` pushes and a weekly schedule. It uses the default
read-only GitHub repository token, with `id-token: write` confined to its job
for authenticated result publication. It has no repository-write permission,
no PAT, no provider login and no `pull_request_target` trigger. Its steps are
on Scorecard's publication allowlist and action references are pinned to
commits. The official v2.5.0 action internally names its scanner image by
version tag; pinning the action does not independently pin that internal image
digest. Complete JSON results are retained as Actions artifacts for 14 days.
We verify the public API and badge in addition to a green workflow run.

## Best Practices

- [Project 15693](https://www.bestpractices.dev/projects/15693)
- [Versioned answers and evidence links](../.bestpractices.json)
- [Official criteria](https://www.bestpractices.dev/en/criteria/0)

The initial saved assessment on 2026-10-19 is **81%, in progress**: 44 criteria
marked Met, four N/A, eleven Unmet and eight unknown. The displayed percentage
is computed by the service; it is not a security score. The project has not
earned the Passing badge. All 67 saved statuses and their justifications were
checked against the public project JSON after submission.

Open items include:

- A source-code SAST tool and a verified lint/warning policy, with findings
  triaged and fixes checked. Image scanning and Scorecard do not replace SAST.
- Complete triage of remaining image vulnerabilities, including age and actual
  exposure, before claiming vulnerability-remediation criteria are met.
- Confirmation of the required secure-design knowledge by a human primary
  developer. AI-generated code and internal reviews do not attest that person's
  knowledge.
- A complete credential-history check, measured test coverage, and verification
  of the TLS key-length and forward-secrecy criteria across supported environments.
- Release tags/versioning and a longer report-response history. This repository
  was created on 2026-10-18; there is no 2-12 month response history to assess.

Some of these are suggested practices, while others prevent Passing. Do not
mark an answer Met merely to improve the percentage. Keep unknown results
explicit, and update evidence links and the public entry together.

MIT licensing, contribution instructions, documented testing and an enabled
GitHub private vulnerability-reporting channel are now in place. The
[security policy](../SECURITY.md) describes support and reporting limits.

## Keeping the results current

Review the public result after each Scorecard run. Edit the Best Practices
entry when evidence changes; `.bestpractices.json` supplies proposed answers
to the service, not an independent verification. The service ignores unknown
(`?`) proposals, so explicitly check any previously asserted answer before
downgrading it. Never substitute a static "Passing" image for the official live
badge.

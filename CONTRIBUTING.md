# Contributing

Bug reports, documentation improvements and pull requests are welcome through
[GitHub](https://github.com/dagoSte/rea-safe-agents). Use the private channel in
[SECURITY.md](SECURITY.md) for suspected vulnerabilities.

For a bug, include the exact commit, operating system, Docker version, command,
expected result and sanitized error. Reproduce with inert files. Never attach
logins, keys, private inputs or unreviewed analysis transcripts.

## Development and validation

Use Python 3.11 or newer. The policy tests use the Python standard library:

```sh
python3 -m unittest discover -s tests -v
git diff --check
```

On Windows use `py -3` instead of `python3`, and also run
`py -3 tests/verify_windows_profile.py`; its native profile lookup must pass,
not skip. CI runs the policy suite on Linux, macOS and Windows. Full runtime
verification is described in [docs/validation.md](docs/validation.md) and
[SETUP.md](SETUP.md); it builds and exercises both real contained clients.
Use a dedicated environment and approved staging. Unit tests alone do not
establish native container behavior on another OS.

Keep changes focused and include tests for security boundaries and meaningful
behavior changes. Explain the problem, final behavior, validation and remaining
limits in the pull request. Update user documentation when behavior changes.
Describe compatibility changes in the README's "What's new" section. Preserve
the existing Python style and keep user-facing project material in English.

Container configuration, protocol parsing, credentials, paths and model egress
are security-sensitive. Preserve deny-by-default checks, resource bounds,
fixed provider destinations and zero host mounts for the agent. Do not add
host execution fallbacks or weaken tests to make CI pass. Dependency updates
need reviewed pins, integrity checks, rebuilt images and renewed verification.

## License and review

Original project code and documentation are distributed under the [MIT
license](LICENSE). Submit only material you have the right to contribute under
that license. Third-party components retain their own licenses and notices.
The maintainer reviews contributions before accepting them. For substantial
security changes, seek a reviewer who did not author the change and record
the evidence; automated and AI-assisted checks do not replace that judgment.

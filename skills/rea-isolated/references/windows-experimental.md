# Experimental Windows support

Windows support is **experimental**. The [public verification run](https://github.com/dagoSte/rea-safe-agents/actions/runs/39140058024/job/117712453235)
passed the native Windows Python policy suite: 64 tests, 62 passed and two
platform-specific skips. The dedicated account-profile test ran separately and
**passed once with zero skips**. These results use native Windows, not a Linux
container pretending to be Windows.

The skipped tests cover the Unix account database and the legacy console
interrupt fixture. Full Docker Desktop integration, including actual mount
translations, contained client dispatch and runtime cleanup on Windows, remains
unverified. Linux/macOS have passed the real paired-container analysis.

When Windows testing is requested, use native Python and Docker Desktop
running Linux containers. Choose narrow local-drive inputs and private control,
output and scratch paths outside protected profile/application state. Configure
account-only Windows ACLs; POSIX mode bits do not set them.

For native Docker Desktop validation, rerun the policy checks and add the real
runtime test:

```powershell
py -3 -m unittest discover -s tests -v
py -3 tests/verify_windows_profile.py
py -3 tests/verify_runtime.py --context desktop-linux --scratch-root "C:\REA Verification"
```

Create the private scratch directory first and use the actual inspected Docker
context. The Windows account-profile lookup must pass, never skip. The real
two-client ZIP test must also pass on that Windows host. Confirm exact read-only
mount translations, resource limits, network isolation, cleanup and both clients'
real tool dispatch. Passing policy CI alone does not establish Docker runtime
containment or complete this experimental platform's validation.

Do not substitute a Linux container on macOS for these native Windows results.

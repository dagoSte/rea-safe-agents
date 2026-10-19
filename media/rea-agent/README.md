# REA Safe Agent overview film

[`rea-agent-explainer.mp4`](rea-agent-explainer.mp4): 68 seconds, 1920 × 1080 at
30 fps, English voice-over, captions in [SRT](rea-agent-explainer.srt) and
[VTT](rea-agent-explainer.vtt). [Poster](poster.png).

## What it shows

| Time | On screen | Voice-over |
| --- | --- | --- |
| 0:00 | REA Safe Agent | REA Safe Agent is a skill that builds a safer, contained environment for analyzing files with REA. |
| 0:07 | Untrusted files. Powerful agents. | Use it when your agent must analyze a file you don't trust. That file can hand the agent instructions, not just evidence. |
| 0:15 | Inspect. Understand. Close. | Pick one archive. REA opens it, lists its contents and closes it; your agent explains the evidence. |
| 0:23 | Only approved file copies | Only reviewed copies, pinned by size and hash, reach REA. Your original folder stays outside. |
| 0:30 | Separate containers. Restricted tools. | REA and your agent run in separate restricted containers. The agent has no host mounts, and the host controller allows only approved tools, including read-only Ghidra queries. |
| 0:43 | Controlled model access | Neither container has external network. Each agent uses your own subscription, and what it reads from your approved files can reach your model service. |
| 0:53 | Static. Contained. Not zero risk. | The file is never executed. Risk goes down, but it never reaches zero. |
| 0:59 | Verify. Repeat after changes. | Verify the boundaries. Repeat after every change. |
| 1:03 | Read SETUP.md | (no voice-over) |

The diagrams are explanatory illustrations, not captured software. Every claim
in the film is taken from the [README](../../README.md), [SETUP.md](../../SETUP.md),
the [client guide](../../skills/rea-isolated/references/clients.md), the
[security model](../../skills/rea-isolated/references/security-model.md) and the
[validation record](../../docs/validation.md).

## How it was made

- Code-rendered motion graphics (motion-studio's launch-film style), rendered
  locally in headless Chromium with an original synthesized score.
- Voice-over: Grok Voice TTS 1.0, voice "leo", through OpenRouter; about
  USD 0.02 in total across all takes.
- Mastered to −16 LUFS integrated loudness and encoded as H.264 with BT.709,
  limited-range colour tags.
- Two independent reviews with no part in making it checked the film against
  the brief, the documentation and motion-studio's craft rules. Their must-fix
  findings were corrected: a platform claim, the visibility of the Ghidra
  queries, text size and a colour-range error in the encode.

Developed by Stefano D'Agostino. Built on
[REA — Reverse Engineer Anything](https://github.com/morluto/rea).

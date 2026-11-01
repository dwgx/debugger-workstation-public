STATUS: DONE — 2026-11-01. This file read `STATUS: BLOCKED` from 2026-10-03 until today. The blind
spot it was opened for is not fixed; it is measured, declared in `manifests/tools.json` + the
verifier's own docstring, and deliberately left. The analysis that was going to live here was
written afterwards in `.agent/tools-manifest.md:330-340` ("Open finding 1"), which is the record.
This file exists only because `skills/debugger-review/SKILL.md:17` cites it.

# Tool invocation blind spots: "root variable + bare name"

Opened 2026-10-03 against `scripts/verify-tools-manifest.py` + `manifests/tools.json`, abandoned at
seven lines when the session was paused. The same target was completed later and is committed:
`.agent/tools-manifest.md` (STATUS: DONE) and `scripts/verify-tools-manifest.py`.

The blind spot, as measured there: Android SDK build-tools are reached by joining a **bare name**
onto an absolute **directory** root — `scripts/mobile-lab.ps1:58-59` and
`mobile-lab/lab/build/build-apk.mjs:75-76` hold the build-tools directory, and `aapt2.exe` /
`d8.bat` / `zipalign.exe` / `apksigner.bat` are launched from it at `build-apk.mjs:210,268,303,304,322`.
An absolute-*executable*-path extractor cannot see that shape, so none of the four is declared and
`mobile-lab` has no `tools.json` entry at all.

It is kept, not widened away: resolving variables across files to catch that shape automatically
would fail *closed* on a real tool. Closing it needs a decision about whether `mobile-lab` gets its
own `tools.json` category — an Owner call, recorded as Open finding 1, not a bug in the gate.

If `skills/debugger-review/SKILL.md` ever drops its citation to this file, delete it: there is no
content here that is not in `.agent/tools-manifest.md`.

# Curriculum — reverse workstation, zero to competent

Ordered training path across our capability domains. Companion to
`knowledge-corpus.md` (note IDs `N-xx` refer to that file's source ledger `S1-S14`).

Rules that make this a curriculum and not a reading list:

- **Every stage names its pass condition, and the pass condition is an exit code or an
  observable** — never "understand X".
- **Every stage requires a negative control.** A stage you can pass without ever being wrong
  has not been passed.
- **Every exercise uses material this station owns or hosts on loopback.** No third-party
  target, no public service, no downloaded sample. `AGENTS.md` §5 and the
  `crackme-corpus/README.md` stop lines are the constraint; the red line in
  `knowledge-corpus.md` §11 (no offensive tooling, no DRM/attestation/anti-bot circumvention)
  applies to every exercise below.
- Stages marked **[AUTHOR]** do not exist yet in this repo and are the honest backlog.

**Stage count: 13 (Stage 0 … Stage 12).**

---

## Stage 0 — Evidence discipline (the floor; do this first, once)

**Why first.** Every other stage's pass condition is worthless if you cannot tell a check
that fires from a check that cannot. `crackme-corpus/README.md` already states the rule
("A check that cannot fail proves nothing"); this stage makes it muscle memory before any
lane is opened.

**Exercise.** Take one assertion in an existing lab loop and break it on purpose.
Recommended first victim: `web-reverse/tools/loop.mjs`, the 401 negative control.

**Pass condition.**
- Mutating the check makes the lab's loop exit non-zero.
- Restoring it returns the loop to exit 0.
- You can state, in one sentence, what the unmodified check was asserting.

**Negative control (required).** Run the lab with the *assertion removed* rather than
inverted. It must fail. If a removed assertion still passes, the check was decorative and
that is the finding.

**Common wrong turn.** Breaking something and calling the non-zero exit "a bug in the lab".
Confirm which side changed before concluding anything.

**Sources.** station `crackme-corpus/README.md`; `mandiant/capa` `tests/fixtures/features/README.md` (S5) — note how a mature project encodes `expected: false` fixtures per sample *and* per location.

---

## Stage 1 — Triage and file-format literacy

**Why here.** Everything else reads bytes through a format assumption. A wrong format
assumption is the classic "confident, complete, wrong" failure, and it is cheapest to learn
to catch on a format we built ourselves.

**Exercise A — recover a record layout from bytes.** `crackme-corpus` **c05** (magic header +
packed 20-byte records, key derived from live data).

**Exercise B — author a format note.** Using the Playdate format notes as the model
(`formats/pdex.md`, `formats/pdz.md`), write a one-page format description for c05's blob
that contains: the magic constant with its hex value, the endianness **and the evidence for
it**, every field with offset/length/type, and one checkable invariant (a checksum, a length
relation, or a round-trip).

**Pass condition.**
- `python crackme-corpus\tools\loop.py --only c05` exits 0.
- The recovered key is accepted by the binary itself (`ACCEPTED`), not just by your code.
- Your format note contains at least one **derived relation**, e.g. `bss = memsz - filesz`
  style, that would break if a field width or endianness were wrong.
- Your note states the version/build it was derived from.

**Negative control (required).** Parse the decoy records. `crackme-corpus/README.md:46`:
"c05 mixes **decoy records** into the live stream | not filtering them yields a wrong digest".
Your parser must reject the decoys; a parser that returns *a* digest is not finished.

**Common wrong turn.** Inferring endianness from a constant-looking field instead of a
varying one (N-17), or filling the field table from one dump so the note "works" on exactly
one file.

**Sources.** N-09, N-16, N-17, N-18; S1.

---

## Stage 2 — Native: recovering real control flow

**Why here.** This is the core of native RE, and our own corpus already has the two
canonical shapes with published answers.

**Exercise.** `crackme-corpus` **c01** (string table, byte rotation + XOR mask), then
**c02** (control-flow flattening behind a dispatcher state machine).

**Pass condition.**
- `python crackme-corpus\tools\loop.py --only c01 --only c02` exits 0.
- c01: the recovered password is `C01-TABLE-XOR-9F2A` **and** is accepted by the binary.
- c02: you produce the state order (`0x1C → 0x07 → 0x4A → 0x35 → 0x11 → 0x2E → 0x59 → 0x41`)
  from the dispatcher constants, not from the answer key.
- Both solvers run with `--no-build` against the committed binaries — i.e. nothing in the
  loop depends on reading the source.

**Negative control (required).** `strings c01-stringobf.exe | grep FLAG` returns
`FLAG{...}` and it is **wrong** (`crackme-corpus/README.md:45`: c01 ships a plaintext fake).
Confirm your answer came from the decode, not from the binary's data section.

**Common wrong turn.** Reading the dispatcher linearly instead of walking the state graph;
treating the flattened CFG as noise and reporting "the function is obfuscated".

**Sources.** station `crackme-corpus/README.md`; N-15 (annotations rename, they do not prove).

---

## Stage 3 — Native: anti-analysis as a subject, on a sample we own

**Why here.** This is where "recompute, never assume" is the entire job, and c03 is built
so the shortcut fails loudly.

**Exercise.** `crackme-corpus` **c03** (anti-debug guard + rolling-XOR seal + FNV-1a
integrity check).

**Pass condition.**
- `python tools\loop.py --only c01` and `python tools\loop.py --only c02` each exit 0
  (`--only` takes a single id — `tools/loop.py:216` filters on equality — so run them one at
  a time; the full `python tools\loop.py` covers both).
- c01: the recovered password is `C01-TABLE-XOR-9F2A` **and** is accepted by the binary.
- c02: you can produce the dispatcher's state order from the jump-table constants in the
  binary, and the recovered password `FL4T-STATE-7B` is accepted by the binary.
- Both solvers run with `--no-build` against the committed binaries — i.e. nothing in the
  loop depends on reading the source.

**Common wrong turn.** Patching the integrity check out instead of recomputing it. That is
the "suppress the check" move the station charter rejects; c03 exists to be *analysed*, and
`crackme-corpus/README.md:113-115` says so explicitly.

**Sources.** station `crackme-corpus/README.md`; N-05 (label what you observed vs assumed).

---

## Stage 4 — Headless native depth and differential analysis

**Why here.** Single-binary analysis is Stage 2-3. The step up is comparing two artifacts,
which is where function-hash diffing, P-code and CFG authoring earn their keep — and our
station already has the toolchain and the sample.

**Exercise.** `headless-lab`: two builds of one source (`core_v1.dll` from
`cl /LD /O1` and `core_v2.dll` from the same source with `-DLAB_MASK=0x3C`). Use
`scripts\ghidra-headless.ps1` with `FunctionHashes.java` and `DiffPrograms.java` to
inventory both and diff them; then use the `/pcode`, `/cfg`, `/create_struct` and
`/resolve_type` routes on one changed function.

**Pass condition.**
- The diff reports exactly the functions that genuinely differ, and the difference is
  attributable to the one compile-time constant.
- `/cfg?address=<changed function>` returns a real CFG (≥2 basic blocks, with edges).
- `/pcode?address=<changed function>` returns ops each carrying the address they came from.
- A struct you author via `/create_struct` and apply changes the disassembly view in the way
  you predicted.

**Negative control (required, and this is the good one).** Run `DiffPrograms` with the same
manifest **twice**. It must report zero `CHANGED`. A differ that always finds changes is
indistinguishable from a working differ only when it never runs on a matching pair.

**Common wrong turn.** Diffing two builds of *different* sources and calling every differing
line a finding. Also: treating the three newly implemented routes as verified because the
code is written — `headless-lab/README.md` marks them "written, compile unverified", and
that label is the pass condition's precondition.

**Sources.** station `headless-lab/README.md`; N-05.

---

## Stage 5 — Managed: decompilation as dataflow, not as text

**Why here.** Managed code looks like source and is not. The skill is reading a
decompilation and re-implementing a transform, which is a different muscle from Stage 2.

**Exercise.** `managed-lab` **m01 → m05** in order: string encryption (keystream XOR +
odd-index swap), CFF + opaque predicates + decoy block, base64 payload in an embedded
resource with a seed derived from the resource name, a hand-rolled header with FNV-1a/32,
and a P/Invoke boundary where the key is in `labnative.dll` rather than in the managed code.

**Pass condition.**
- `powershell -File managed-lab\tools\build.ps1` then
  `node managed-lab\tools\loop.mjs` exits 0.
- The current committed baseline is **27 checks, 27 pass, exit 0**
  (`managed-lab/README.md`; transcript in `notes/2026-09-30-managed-native-depth.md`).
  Not regressing below that baseline is the bar; a lower count is a failure even at exit 0.
- For m05 you can state *where* the key lives (native side) before you look for it — the
  lesson is the boundary, not the string.

**Negative control (required).** m01 is designed so that applying only one of the two
transform layers yields "plausible garbage" (`managed-lab/README.md`, "Why these five").
Show the one-layer output and show that it is wrong. m02 additionally requires rejecting a
decoy block and starting at the *real* entry state (`Boot[1]`, not `Boot[0]`).

**Common wrong turn.** Accepting a decompiled control-flow shape that "cannot happen" as
evidence of obfuscation instead of as evidence that your type model is wrong (N-15).

**Sources.** station `managed-lab/README.md`, `managed-lab/IL-READING.md`;
N-19, N-20, N-21.

---

## Stage 6 — Crypto/JWT: signature checked ≠ token validated

**Why here.** The lane's whole lesson is that a green check from a library is not a
verdict on the deployment. It also gives the cleanest negative-control material on the
station, because every weakness class has a "correct" twin.

**Exercise A — run the lane.** `powershell -File scripts\crypto-lab.ps1 loop` (or
`node crypto-lab\tools\loop.mjs`).

**Exercise B — write a verdict in the N-22..N-26 shape.** Take one token and report, as
separate lines: signature result, algorithm pin result, claim validation performed (which
of `exp`/`nbf`/`iss`/`aud`), key provenance, token type. Each line cites the check that
produced it.

**Exercise C [AUTHOR].** Extend `crypto-lab` with a fixture whose token is (a) `alg`-selected,
(b) missing `iss`, (c) missing `aud`, and (d) `typ`-less — i.e. the four ways a token can be
signed and still be wrong for the verifier. The analyzer must classify each per RFC 8725
§3.1/3.8/3.9/3.11. This is the one crypto gap in the current corpus.

**Pass condition.**
- The loop exits 0, and its internal self-check exits **4** when the finding set is mutated —
  i.e. the pass/fail logic is itself testable.
- Your verdict distinguishes "signature checked" from "exp/aud/iss checked" in the same
  report, with the verifier's own argument list quoted.
- For the `alg`-confusion fixture: the forged HS256-over-public-key token is **rejected**
  when the verifier pins `algorithms=["ES256"]`, and accepted when it does not — both
  directions observed.

**Negative control (required).** Feed a token with `"alg":"none"`. It must be classified as
`unsigned-none` and the analyzer must exit non-zero on it. A "no findings" result on an
unsigned token is the failure this stage exists to prevent.

**Common wrong turns.**
- Treating a modern library's mitigation as a clean bill of health. PyJWT's public-key-shaped
  MAC detection blocks *one* shape (OWASP JWT cheat sheet `:274`); a negative result is
  evidence about that shape, not about the deployment.
- Claiming a key-confusion bypass because you *constructed* a token. The pass condition is
  the verifier's behaviour on it, in both directions.

**Sources.** N-22, N-23, N-24, N-25, N-26; S10 (`JSON_Web_Token_Cheat_Sheet.md`); S11
(RFC 8725 §2.1, §2.7-2.9, §3.1-3.12); station `crypto-lab/README.md`.

---

## Stage 7 — Web/JavaScript: prove the algorithm with a ladder

**Why here.** It is the station's most complete worked example of the discipline, and the
ladder generalises to every lane.

**Exercise.** `powershell -File scripts\web-reverse-lab.ps1 loop`
(or `node web-reverse\tools\loop.mjs`; `cd web-reverse\static && npm install` once).

**Pass condition — all four rungs, in order.**
1. No signature headers → `HTTP 401 {"ok":false,"error":"missing-signature-headers"}`.
2. Verbatim capture replay → `409 replayed-signature`.
3. **Recomputed** signature → `200 accepted`.
4. Forged body with your own key → `200 accepted`, and independently
   `sha256(key)[0:16] == the server's keyId`.

Rung 2 and rung 3 are different claims. Only reaching rung 3 means the algorithm was
recovered; only rung 4 means the key was.

**Negative control (required).** Rung 1 *is* the negative control — the gate is not
decoration. Do not skip it; a 200 on an unsigned request means you are not testing the
thing you think you are.

**Common wrong turns.**
- Calling the deobfuscation "done" when the string table is readable but the key is still a
  literal nobody uses (N-34).
- Reporting the XHR tap as evidence of server-side enforcement; it is evidence of the
  *client's* behaviour. `web-reverse/README.md` keeps "what the target sees of us" as its
  own section for this reason (N-27).

**Sources.** station `web-reverse/README.md`; N-33, N-34; N-27.

---

## Stage 8 — Network / protocol: format *and* state machine

**Why here.** The pipeline (split → cluster → align → relate) is a skill, and it has a hard
precondition most people miss: you need several messages of each type, from several sessions.

**Exercise A — the lane.** `node net-reverse\tools\loop.mjs`.

**Exercise B — format inference on our own traffic.** Take a loopback capture produced by
Exercise A and, by hand or with Netzob, (i) split on a recurring delimiter, (ii) cluster by
the field that names the message type, (iii) run a sequence alignment inside one cluster to
separate static from variable regions, (iv) find at least one field relation
(e.g. a length field equal to another field's size).

**Exercise C [AUTHOR].** A small loopback protocol of our own with ≥5 captured sessions and
≥2 messages per type, so the alignment precondition is satisfiable, plus at least one
deliberately *invalid* transition to test state-machine inference. Then write it up in the
Fichero document shape: byte-exact tables, a "commands that do NOT work" table, and an
end-to-end sequence with its completion signal and timeout.

**Pass condition.**
- Exercise A exits 0, with the three documented defects either fixed or explicitly reported.
- Exercise B yields a format in which at least one field is provably variable and at least
  one relation is stated in *typed* form (value-of-A = size-of-B), not as prose.
- Exercise C's document contains: a "no response" table, a per-message-type response shape,
  and the end-to-end sequence with the terminal condition (a specific byte or string you
  waited for).

**Negative control (required).** Feed the parser a message of a known type with a corrupted
length field. It must be **rejected**. A parser that accepts it has inferred a field boundary
without proving it. The second negative control is the invalid transition: the state machine
must refuse a message that is well-formed but out of order — that is the difference between
a dissector and a protocol model (N-12).

**Common wrong turns.**
- One capture, one session: no alignment is possible, so any "field" you report is a guess.
- Treating a Wireshark dissector's success as protocol validation.

**Sources.** N-11, N-12, N-13, N-27, N-28; S3 (`techge/PRE-list` — the NetT/ExeT × PF/PFSM
matrix, and its own warning that most entries are "Please review" and most research ships no
code); S4 (`netzob` tutorial, which carries a 1.x-obsolete warning to copy first); station
`net-reverse/README.md`.

---

## Stage 9 — Forensics / memory: refusals are results

**Why here.** The lane where "confident, complete, wrong" is the default failure, because
the tools will happily produce output on an image they cannot actually read.

**Exercise.** `powershell -File scripts\forensics-lab.ps1 loop`
(or `node forensics-lab\tools\loop.mjs`). Record the Volatility 3 refusal table, which is
already asserted by the loop: `frameworkinfo.FrameworkInfo` exit 0, `banners` exit 0,
`windows.pslist` exit 1 (`plugins.PsList.kernel.layer_name`), `yarascan.YaraScan` exit 1
(`plugins.YaraScan.primary`).

**Pass condition.**
- The loop exits 0 **including** the two asserted refusals. The refusals are part of the
  pass, not a gap in it.
- `scripts\forensics-lab.ps1 doctor` reproduces the table on demand.
- Your write-up separates what real Volatility 3 said from what `tools\triage.mjs` emulated,
  exactly as `forensics-lab/README.md` does.
- Every memory finding you report names the acquisition and the OS build it depends on.

**Negative control (required).** Forcing a translation layer (`-e`, `--single-location`,
`--stackers`) and showing that no kernel layer is built. The forced attempt is the negative
control for "we made the tool run": it must fail, and its failure is the evidence that the
refusal is real and not a missing flag.

**Common wrong turns.**
- Reporting forced output as analysis (N-06).
- Counting two front-ends over one parser as two independent witnesses (N-30).
- Generalising a Linux memory result to a product finding while no matching `vmlinux`/symbol
  pack exists (N-29).

**Sources.** N-06, N-07, N-29, N-30; S9 (`volatility3` README: symbol packs, checksums,
manual `dwarf2json` for Mac/Linux, Linux exhaustiveness caveat); station
`forensics-lab/README.md`.

---

## Stage 10 — Mobile / Android: state the ceiling first

**Why here.** The lane where the easiest thing to produce is a convincing fake. The training
objective is refusal to over-claim, as much as analysis skill.

**Exercise.** `node mobile-lab\tools\loop.mjs` (or
`powershell -File scripts\mobile-lab.ps1`), including the Frida-authoring half and the
optional `pyelftools` oracle.

**Pass condition.**
- The loop exits 0.
- The report contains the ceiling section: what the Frida emulator does and does not prove,
  and the `.so` substitution "stated plainly" (`mobile-lab/README.md`).
- The oracle (pyelftools) result is presented as the *independent* check on the substitution,
  and the emulator result is not offered as a runtime proof.

**Negative control (required).** The substituted library must be shown to fail the oracle when
the substitution is wrong. A "bypass" that the oracle cannot distinguish from the original
file is not a bypass.

**Exercise B [AUTHOR].** A self-authored APK with a JNI boundary (Java logic calling a small
`lib/arm64-v8a/*.so`) so the managed/native split is a real analysis problem rather than a
description. Author it in this repo; do not download a sample.

**Common wrong turns and the red line.**
- Writing up a local hook or substituted `.so` as a working bypass. It is not: the
  substituted file is not a device-valid library.
- Play Integrity / App Attest: record which API an app uses, that the verdict is validated
  **server-side**, and that SafetyNet was turned down in January 2025 — then stop. No bypass
  technique, no attestation hook, no pinning-strip recipe. `knowledge-corpus.md` N-32 and
  §11 record this boundary deliberately.

**Sources.** N-31, N-32; S10 (`Mobile_Application_Security_Cheat_Sheet.md:275-280, 388-391`);
station `mobile-lab/README.md`, `mobile-lab/pinning.md`.

---

## Stage 11 — Fuzzing / differential: harness before target

**Why here.** Last, because it composes everything above and because it has an **unresolved
toolchain precondition on this box that the Owner must decide, not the trainee.**

**The toolchain problem, stated plainly.** AFL++ needs `afl-clang-fast` / `afl-clang-lto`
(PCGUARD or LTO). This machine has **MSVC 2022 and no gcc**, and MSVC offers no equivalent
coverage instrumentation. So there is no honest "just run it" path here today. Two options,
both legitimate:

- **Option A (requires Owner authorization):** install clang/LLVM or use WSL, then fuzz a
  harness over **our own** c05 blob parser (`crackme-corpus/challenges/c05-binary-format/src/c05_blob.c`)
  and **our own** m04 record reader. Both are code this repo owns. No third-party target.
- **Option B (zero install, works today):** run a deterministic mutation campaign with a
  hand-written reach check. Then the pass condition below is satisfied by the *check*, not
  by the fuzzer.

**Pass condition.**
- **Harness correctness is demonstrated before any result is reported.** Concretely, the
  N-03 check: coverage/edge count is in a plausible range, and if no new coverage appears
  within the first minutes, the harness is declared broken rather than the target declared
  safe.
- The harness reads from a **file or stdin**, never over a socket, and never through a GUI
  (N-35).
- Every finding ships as testcase + exact command, and the command has been re-run once
  (N-38).
- Instability handling follows N-14: only functions that do **not** touch the fuzz data are
  excluded from instrumentation; parser functions that are noisy are kept and their
  instability accepted.
- If you used persistent mode and it is unstable while the non-persistent build is fine, you
  conclude the target keeps internal state and disable persistent mode (N-14).

**Negative control (required).** Run the mutation campaign against a **known-good** input set
and against a deliberately broken harness (one that never reaches the parser). The broken
harness must produce zero findings *for a reason you can name* — because it never reached the
parser, not because the parser is safe. Then, and only then, is a zero-finding result on the
real harness meaningful.

**Common wrong turns.** Zero crashes after an hour on a service fuzzed over its socket; a
"crash" reported with a 4 MB testcase that nobody minimised; a 100%-stable harness that
excluded the parser from instrumentation.

**Sources.** N-03, N-14, N-35, N-36, N-37, N-38; S7 (`AFLplusplus` docs — AGPL-3.0, read for
method; no code vendored), S8 (`oss-fuzz` — Apache-2.0).

---

## Stage 12 — Capstone: produce a note and a mission report

**Why last.** It trains the layer this whole corpus exists for, and it is the deliverable
shape the station will actually consume.

**Exercise.** Pick one real finding from any earlier stage. Produce (a) a knowledge note and
(b) a one-page mission report, both in the station's own formats.

**Pass condition — note.**
- Contains all four fields: **Practice / Preconditions / Pass signal / Negative control.**
  A note missing any one is rejected.
- Cites a specific file in a specific source, and records that source's **license** and the
  **retrieval date**.
- Every claim is labelled by epistemic status (observed / read from code / assumed), the way
  `0xMH/fichero-printer/docs/PROTOCOL.md` labels its own tables
  ("verified on hardware" vs "from APK — NOT TESTED").
- Contains at least one honest gap ("TODO" is allowed; a confident guess is not).

**Pass condition — mission report.**
- Separates static capability inference from observed behavior (N-04).
- States, for every claim, what observable supported it.
- States what the analysis **cannot** conclude, and what acquisition or environment would be
  needed to conclude it.
- Names any tool that refused, with its exit code and error text (N-06).

**Negative control (required).** Have another reader try to break the report by asking
"how do you know that is true?" for three claims. Any claim that cannot be traced to an
observable is the finding of this stage.

**Common wrong turns.** A report that is a list of tool outputs; a note with a "limitations"
paragraph that is a single generic sentence; a source list with no licenses (the corpus
ledger in `knowledge-corpus.md` §10 is the model — including the sources that were *not*
usable).

**Sources.** N-01 … N-38; S2, S1 (the two documents whose confidence labelling is the
exemplar); station `AGENTS.md` §7 and `docs/AGENT_EVOLUTION.md` for where durable notes go.

---

## Path summary

| Stage | Domain | Primary material | Status |
|---|---|---|---|
| 0 | Evidence discipline | any lab loop | exists |
| 1 | Triage / file formats | crackme-corpus c05 | exists (format doc is yours to write) |
| 2 | Native control flow | c01, c02 | exists |
| 3 | Native anti-analysis | c03 | exists |
| 4 | Headless native + diff | headless-lab v1/v2 | exists |
| 5 | Managed / .NET | managed-lab m01-m05 | exists |
| 6 | Crypto / JWT | crypto-lab + RFC 8725 | exists; **[AUTHOR]** fixture needed |
| 7 | Web / JS | web-reverse | exists |
| 8 | Network / protocol | net-reverse | exists; **[AUTHOR]** protocol+corpus needed |
| 9 | Forensics / memory | forensics-lab | exists |
| 10 | Mobile / Android | mobile-lab | exists; **[AUTHOR]** JNI APK needed |
| 11 | Fuzzing / differential | — | **toolchain decision required**; zero-install fallback defined |
| 12 | Capstone | all of the above | exists as a deliverable shape |

**Two Owner decisions block full completion:** (1) authorize a clang/WSL toolchain for Stage 11,
or accept the zero-install fallback as the lane's definition of done; (2) approve the four
`[AUTHOR]` fixtures (crypto `alg`/`iss`/`aud`/`typ` token set, loopback protocol with ≥5
sessions, self-authored JNI APK). All three are our own artifacts, built in this repo —
none requires a third-party target, a download, or a licence question.

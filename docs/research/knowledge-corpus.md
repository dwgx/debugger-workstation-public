# Knowledge corpus — reverse workstation

Distilled reverse-engineering practice for this station. Working notes; `.agent/` is
gitignored. Fold the conclusions into the committed wiki before they count as station truth.

**All retrieval dates: 2026-09-30.** Every note cites a file that was actually opened in
this session (see §10 Source ledger). Claims about repos that were not opened do not appear
here.

---

## 0. The contract every note obeys

A note is only worth keeping if it carries four fields. The station already enforces this
in `crackme-corpus/README.md` ("the artifact is the judge", "a check that cannot fail
proves nothing"); this corpus applies the same rule to *knowledge* instead of to code.

| Field | Question it answers | Failure mode it blocks |
|---|---|---|
| **Practice** | What do I actually do? | Cargo-cult recitation |
| **Preconditions** | Under what boundary conditions is it true? | Advice that is worthless or harmful out of context |
| **Pass signal** | What observable distinguishes a real result from a plausible one? | "Confident, complete, wrong" |
| **Negative control** | What does the *fake* version of this same result look like? | A check that cannot fail |

Two extras appear where they matter and are marked **Boundary** (where the practice is known
to fail) and **Provenance** (how strongly the claim is supported).

A fifth, non-negotiable habit: **label the epistemic status of every finding.** The single
best external model I found is a protocol reference that carries its own confidence in the
section headings — `0xMH/fichero-printer/docs/PROTOCOL.md` writes
"*(verified on hardware)*" on the command tables it tested and
"Firmware Update Protocol (AiYin, from APK - NOT TESTED)" on the one it did not, plus an
explicit table of commands that **do not work**. We should write our own findings the same
way, because the alternative is a report that reads identically whether or not anyone
observed it.

---

## 1. Cross-domain method notes

### N-01 — "No match" is not "not present"; know which way your tool can fail
- **Practice:** Static capability detection has a documented, *asymmetric* failure profile. It misses packed code, installers/run-time-packaged apps, and behavior hidden behind wrapper/helper functions and loops.
- **Preconditions:** The sample is a native binary analysed by a signature/capability engine; the packer detection rule did not fire first.
- **Pass signal:** The tool warns explicitly. In capa, `doc/limitations.md:1-4` says packed input "may be misleading or incomplete" and capa emits a warning; `doc/limitations.md:13-35` documents that a rule matching "file creation and execution" on a *parent* function will not fire when the matching lives in a wrapper child, because wrappers and layered-language call layers are the normal case, not the exception.
- **Negative control:** A clean report on a packed or installer-wrapped sample. Fake shape: a tidy capability list with no matches, presented as "this binary is benign".
- **Boundary:** Loop and thread scope are approximated, not implemented (`doc/limitations.md:38-45`); a wrapper-heavy binary systematically under-reports.
- **Source:** `mandiant/capa` — Apache-2.0 — `doc/limitations.md`.

### N-02 — A detection with no real positive example is unproven, not "probably fine"
- **Practice:** In a mature detection corpus, a rule without a real-world sample example is demoted to a staging area, not shipped as a finding. Mandiant's capa-rules repo routes such rules to `nursery/`: "Examples of things that would place a rule into the nursery: no real-world examples, missing categorization, (maybe) questions about fidelity" (`README.md:153-163`).
- **Preconditions:** You are writing or trusting a rule/detector/signature that someone else will rely on.
- **Pass signal:** The rule's `meta.examples` lists a real sample **and a location inside it** — `capa-rules/README.md:39-40` shows `- C91887D861D9BD4A5872249B641BC9F9:0x401A77`, i.e. hash *and* address, not a prose claim.
- **Negative control:** A rule justified only by "this is how it usually looks". Fake shape: a pattern match with no sample behind it that happens to fire on a benign file.
- **Application here:** Any new `capa`-style detector, YARA rule, or lab check we add should carry a sample + offset, or be explicitly marked unproven.
- **Source:** `mandiant/capa-rules` — Apache-2.0 — `README.md`.

### N-03 — Instrument the instrument before trusting the measurement
- **Practice:** Before interpreting any metric a tool reports, check that the metric is in a physically possible range. A range violation means the *measurement* is wrong, not the subject.
- **Preconditions:** A coverage-guided run (fuzzer) or an equivalent coverage report.
- **Pass signal:** AFL++ documents both bounds explicitly (`docs/afl-fuzz_approach.md:183-196`): absolute map counts **below ~200** mean one of three things — the program is trivially simple, it is not instrumented properly (e.g. linked against a non-instrumented copy of the target library), or it bails out prematurely on your inputs; percentages **over ~70%** mean the bitmap is saturating and new states are hard to distinguish. The equivalent practice on a code-coverage pipeline: generate a coverage report against the aggregated corpus "to get a good understanding of fuzz testing quality" rather than assuming the harness reaches the parser.
- **Negative control:** A fuzzer that runs for hours, reports "0 crashes", and whose map density is 12/29907. Fake shape: "the parser is safe" derived from a run that never reached the parser.
- **Boundary:** "If the tool is not finding new paths within several minutes of starting, you're probably not invoking the target binary correctly" (`docs/afl-fuzz_approach.md:108-117`) — the same sentence is the single most useful triage rule in the file.
- **Source:** `AFLplusplus/AFLplusplus` — AGPL-3.0 — `docs/afl-fuzz_approach.md`; `google/oss-fuzz` — Apache-2.0 — `docs/advanced-topics/code_coverage.md:44-50`.

### N-04 — Separate "what the bytes can do" from "what it did"
- **Practice:** Treat capability inference and observed behavior as two different deliverables with two different evidence standards. capa's entire product is the first; the second needs a trace, a sandbox, or an instrumented run.
- **Preconditions:** Any static triage output being written up as a conclusion.
- **Pass signal:** The two claims appear in different sections with different provenance labels. `doc/limitations.md:48-51` keeps ATT&CK/MAEC/MBC tagging in a *separate* section from the matcher semantics, and `tests/fixtures/features/README.md` encodes expected results per feature, per location, including explicit `expected: false` cases (e.g. `characteristic: loop` asserted absent on a specific function of a specific sample).
- **Negative control:** A report that says "the binary persists via a Windows service" and cites a string match. Fake shape: static evidence phrased in the past tense.
- **Source:** `mandiant/capa` — Apache-2.0 — `doc/limitations.md`, `tests/fixtures/features/README.md`.

### N-05 — "Verified / inferred / untested" belongs in the artifact, not in your head
- **Practice:** Split findings into three buckets and never let them blur: (a) observed on a real target, (b) read out of code, (c) assumed. The Fichero protocol reference does exactly this and it changes how the document reads.
- **Preconditions:** Any note or report that will outlive the session.
- **Pass signal:** The bucketing is visible in the text. `docs/PROTOCOL.md:31` "Info Commands (verified on hardware)" vs `:159` "Firmware Update Protocol (AiYin, from APK — NOT TESTED)"; the Playdate notes open with "All of the content herein was gleaned from reverse-engineering … as such there may be mistakes or missing information" (`readme.md:3`) and then leave honest holes in place (`formats/luac.md:9` "Header Differences: TODO").
- **Negative control:** A document where every table looks equally trustworthy. Fake shape: a firmware-update spec quoted next to a battery-voltage reading, both stated flatly.
- **Source:** `0xMH/fichero-printer` — no license file; `cranksters/playdate-reverse-engineering` — CC0-1.0.

### N-06 — A refusal is a result; record it instead of routing around it
- **Practice:** When a canonical tool declines to analyse your artifact, that refusal is a finding about your acquisition, not an obstacle to route around. Record the exact plugin, exit code and error text.
- **Preconditions:** The tool is a real, correctly installed instance (not a stand-in), and you did not force a translation layer to fake success.
- **Pass signal:** A per-plugin table of exit codes. This station already does it in `forensics-lab/README.md` (§"Volatility 3: the real boundary, recorded"): `frameworkinfo`/`banners` exit 0, `windows.pslist` and `yarascan.YaraScan` exit 1 with named error strings, and the assertion that "it cannot" is a claim requiring evidence. Volatility's own bug-report template (`README.md:108-118`) requires you to state *the suspected operating system of the memory sample* — i.e. the OS identity is an input to the analysis, not a detail.
- **Negative control:** Forcing `-e` / `--single-location` / `--stackers` until something prints, then reporting the forced output as an analysis. Fake shape: a process list from an image with no kernel layer.
- **Source:** `VolatilityFoundation/volatility3` — VSL-1.0 (non-commercial) — `README.md:64-89`; station `forensics-lab/README.md`.

### N-07 — Bound every finding to a version
- **Practice:** Formats, opcodes, headers and symbol data are all version-scoped. State the version boundary in the same sentence as the claim, and expect a *different* structure on the other side of it.
- **Preconditions:** The artifact is a versioned format (container, bytecode, OS image, ruleset).
- **Pass signal:** The note names both sides of the boundary. Playdate: the Lua runtime is tweaked 5.4.3 with `#define LUA_32BITS = 1`, opcodes are **appended** to keep bytecode from the pre-1.8.0 SDK loadable (`formats/luac.md:1-13,100-112`), and the pre-1.8.0 header has a different structure documented separately (`:114-126`). Volatility: symbol packs "are representative and are complete up to the point of creation"; Windows and Mac are supported, but "due to the ease of compiling Linux kernels and the inability to uniquely distinguish them, an exhaustive set of Linux symbol tables cannot easily be supplied" (`README.md:89`).
- **Negative control:** A parse that "works" and yields plausible structure from the wrong version's layout. Fake shape: correct-looking offsets, garbage field semantics — the worst outcome, because it is indistinguishable from success by inspection.
- **Source:** `cranksters/playdate-reverse-engineering` (CC0-1.0); `VolatilityFoundation/volatility3` (VSL-1.0).

### N-08 — Pin the engine and its ruleset together, or expect silent nonsense
- **Practice:** Rule/detection syntax versions with the engine version. A mismatch should be a loud error, and the error is a version clue, not a bug report.
- **Preconditions:** You have a rule collection and an engine, from anywhere.
- **Pass signal:** Documented failure mode, not a crash: "you must use match the rules major version with the capa major version … otherwise … may lead to errors like `ERROR:lint:invalid rule: injection.yml: invalid rule: unexpected statement: instruction`" (`doc/rules.md:28-37`).
- **Negative control:** Mixing a rule set from a different release and interpreting the resulting empty/partial report as "no behaviour found".
- **Source:** `mandiant/capa` — Apache-2.0 — `doc/rules.md`.

### N-09 — Prove a format by round-trip, not by eyeball
- **Practice:** The strongest available proof that a file-format parser is right is re-encoding: parse → emit → compare bytes with the original. Second best is a checksum field the container itself carries.
- **Preconditions:** You have at least two real samples and, ideally, the toolchain that produced them.
- **Pass signal:** The Playdate tools do this in their README contract: `pdex2elf.py` "Converts a `pdex.bin` to an ELF file that can be analyzed … **or compiled back to the same original `pdex.bin` by `pdc`**" (`readme.md:30`). The container format carries an MD5 of the program segment in its own header (`formats/pdex.md:36`), so a parser can self-check without the source.
- **Negative control:** A parser that reads fields at plausible offsets and produces a plausible object. Fake shape: right field count, wrong field width, no checksum ever compared.
- **Application here:** this is exactly the standard `crackme-corpus` c05 exercise (recover a 20-byte record layout, derive the key from live data) already applies.
- **Source:** `cranksters/playdate-reverse-engineering` — CC0-1.0 — `readme.md`, `formats/pdex.md`, `formats/pdz.md`.

### N-10 — Walk the whole flag space; the interesting bit is the one nobody uses
- **Practice:** Enumerate a header's bitfield and document what each bit *does*, then find the container behavior that the flag actually selects — which is often a DRM/encryption switch you should note as existing and leave alone.
- **Preconditions:** A container format with a flags word.
- **Pass signal:** Documented bit semantics, including a bit with real consequences and an honest note that the mechanism is unknown. Playdate: `flag & 0x40000000` ⇒ "all data after the file header is encrypted … only used by Catalog games as a form of DRM. The encryption method is not yet known" (`formats/pdex.md:28-30`, `formats/pdz.md:12-16`). Entry flags are nested too: `flags & 0x80` = compressed, `flags & 0x7F` = entry type (`formats/pdz.md:38-54`).
- **Negative control:** Reporting the flag word as "flags" without splitting it — which hides the encryption case entirely.
- **Boundary / red line:** the flag is a DRM switch. We record its existence and stop; circumvention is out of scope for this station (`AGENTS.md` §5).
- **Source:** `cranksters/playdate-reverse-engineering` — CC0-1.0.

### N-11 — Alignment finds variable fields; relations find the semantics
- **Practice:** Protocol/message format inference is a four-step pipeline, and the steps are separable on purpose: (1) split on a delimiter that recurs; (2) cluster messages by the field that names the message type; (3) run a **sequence alignment** within each cluster to separate static from variable regions; (4) run a relation finder across fields to recover length/offset semantics.
- **Preconditions:** You have a trace with several messages of *each* type. A single sample per type yields no alignment and no relations — this is the hard precondition, and it is the reason "replay a few times" beats "capture once".
- **Pass signal:** Step 4 produces a *typed* relation, not a guess: in the Netzob tutorial the alignment of `CMDencrypt` yields a static `\x00\x00\x00` between two variable fields, and the relation finder returns `SizeRelation, between 'value' of Field [['n','x06']] and 'size' of Field [['123456test','abcdef']]` (`tutorials/discover_features.rst:236-270`). The output is then usable: the size field's domain becomes a computed `Size(...)` with a stated factor.
- **Negative control:** A single delimiter split presented as "the protocol format". Fake shape: field list that never varies, therefore never proved to be a field boundary.
- **Boundary:** the tutorial itself carries a warning that it targets Netzob 1.x and is slightly obsolete (`:8-10`) — check the API version before copying code.
- **Source:** `netzob/netzob` — GPL-3.0 — `doc/documentation/source/tutorials/discover_features.rst`.

### N-12 — "Format" and "state machine" are separate deliverables with separate proofs
- **Practice:** When documenting a protocol, ship two artifacts: the message **format** (syntax) and the **state machine** (order/semantics). A format alone does not tell you what the server will accept next.
- **Preconditions:** A trace-based analysis (NetT) or execution-trace analysis (ExeT); the source survey separates these input classes and the two output classes (PF, PFSM) explicitly.
- **Pass signal:** The output table in the survey lists, per tool, whether it produces PF and/or PFSM (`README.md:108-112` and the matrix at `:113-185`). Netzob is one of the few rows with all four boxes ticked, and its docs ship a grammar-inference section (automaton / Prefix Tree Acceptor) separate from format inference.
- **Negative control:** A Wireshark dissector that parses each message perfectly but was never validated against a real transition — it decodes the illegal sequence happily.
- **Caveat about the survey itself:** most of its 71 entries are "Please review", and the source-code table (`:263-275`) shows that most research publishes no code. Treat academic PRE tools as vocabulary for the method, not as tools to install.
- **Source:** `techge/PRE-list` — CC0-1.0 — `README.md`; `netzob/netzob` — GPL-3.0.

### N-13 — Exact byte sequences beat prose in a protocol document
- **Practice:** Document commands as literal bytes with the response shape, and mark the "no response" case explicitly. Prose descriptions are where protocol bugs hide.
- **Preconditions:** You can talk to the device or service, or you have a capture.
- **Pass signal:** A table of `bytes → command → response`, plus a **negative table** of commands that produced no response. Fichero has both (`docs/PROTOCOL.md:31-44` verified commands; `:80-88` "Commands That Do NOT Work on D11s" with "No response" per row), and it documents the device-class dimension: enable/stop is `10 FF FE 01`/`10 FF FE 45` for AiYin but `10 FF F1 03`/`10 FF F1 45` for Lujiang, because the SDK's class hierarchy is `D11s -> AiYinNormalDevice -> BaseNormalDevice -> BaseDevice` (`:6-7,108-111`).
- **Negative control:** "Using the wrong ones = printer accepts data silently but never prints" (`:111`). This is the archetype of a silent-accept failure: the target behaves plausibly and produces nothing.
- **Provenance note:** the doc's method section is the model to copy: enumerate the interface, obtain the client, decompile it, trace the class hierarchy, find the class-specific overrides, **then test every discovered command against the actual hardware and document which ones work** (`:184-191`).
- **Source:** `0xMH/fichero-printer` — no license file. Cited for method and structure; nothing vendored.

### N-14 — Stability beats determinism; a partial-coverage stable target beats a full-coverage unstable one
- **Practice:** When a harness or a sample is noisy, do not chase 100% stability by dropping the noisy code. Exclude from instrumentation only functions that **do not touch the fuzz data**; accept the instability of functions that do.
- **Preconditions:** A coverage-guided harness, and the ability to attribute unstable edges to functions.
- **Pass signal:** The rule of thumb is stated as a comparison: "A 100% stable target that covers all edges is the best case. A 90% stable target that covers all edges is, however, better than a 100% stable target that ignores 10% of the edges" (`docs/best_practices.md:120-127`). Attribution method is also given: replay the corpus several times and report lines whose hit counts vary across runs (`:137-140`).
- **Negative control:** Denylisting a hash-map or init function that *does* consume input, then reporting the resulting coverage drop as "the input parser is unreachable".
- **Also:** persistent mode that is unstable while the non-persistent build is fine means the target keeps internal state — "Fuzz such targets **without** persistent mode" (`:142-145`).
- **Source:** `AFLplusplus/AFLplusplus` — AGPL-3.0 — `docs/best_practices.md`.

### N-15 — Annotations rename; they do not prove
- **Practice:** Type annotations, argument names, enum names and imported documentation are *hypotheses about meaning*. Keep them separate from observed values; a renamed constant is still just a number you guessed at.
- **Preconditions:** A decompiler with an annotation database, or any automated naming pass.
- **Pass signal:** The tooling treats naming as a separate, repeatable, overwritable layer — FLARE's MSDN-annotation script backs up the original database first, then imports function/argument descriptions, creates enums for identified constants, and renames them to readable values, all as a post-analysis pass over an existing IDB. The same repo's `argtracker` exists specifically to "identify **static** arguments to functions used within a program … most commonly used to extract arguments to string decoder functions", i.e. the hard part is the argument values, not the parameter names.
- **Negative control:** A decompiled listing where every constant has a meaningful name, read as if the names were recovered facts. Fake shape: `MSG_TYPE_PERSISTENCE = 0x1000` when 0x1000 was only *guessed* to be a type selector.
- **Source:** `mandiant/flare-ida` — Apache-2.0 — `README.md`.

---

## 2. Native / binary format reverse engineering

### N-16 — Anchor a format on constants, not on plausible numbers
- **Practice:** A trustworthy format description cites the literal constant values it anchors on (magic bytes, version codes, guard bytes) and says where each is defined.
- **Preconditions:** You have hexdumped output from a real sample.
- **Pass signal:** Playdate's Lua header table gives offset, type and exact constants — `LUA_SIGNATURE` = `1B 4C 75 61` at offset 0, version `0x03F8` at offset 4, `LUAC_FORMAT` = `00`, `LUAC_DATA` = `19 93 0D 0A 1A 0A`, instruction/integer/number sizes "always 4", and the sentinel values `LUA_INT = 0x5678`, `LUA_NUM = 370.5` (`formats/luac.md:114-126`). Those sentinels are the thing that makes a header parse *checkable*: if the sentinel bytes are not where the table says, the version hypothesis is wrong.
- **Negative control:** A header table written from one dump with no constants, so the same parser "works" on a different version.
- **Source:** `cranksters/playdate-reverse-engineering` — CC0-1.0 — `formats/luac.md`.

### N-17 — Declare endianness, and derive the rest of the layout from a build you can vary
- **Practice:** When a format stores multi-byte integers, decide endianness from a *variable* value (a length, a size that changes between samples), not from a constant field that looks the same either way.
- **Preconditions:** Two or more samples of the same format with a field that actually varies. (The Playdate pdex program header is the canonical example: `p_filesz`, `p_memsz`, `e_entry`, relocation count, all little-endian, and the program data is zlib-compressed — `formats/pdex.md:32-45`.)
- **Pass signal:** Two samples where the same field takes different values and both decode coherently; plus the derived relation `bss_size = p_memsz - p_filesz` (`:49`) — a relation that only holds if both widths and the endianness are right.
- **Negative control:** One sample; endianness chosen by appearance; `p_memsz < p_filesz` unnoticed.
- **Source:** `cranksters/playdate-reverse-engineering` — CC0-1.0 — `formats/pdex.md`.

### N-18 — Know when a container's payload layout is *not* a copy of the source layout
- **Practice:** A build tool's container often merges and re-lays-out sections; read the container's own field semantics instead of assuming the original section table survives.
- **Preconditions:** You have both the tool's documentation/strings and samples.
- **Pass signal:** The description explains the merge explicitly: the program segment "usually consisting of the `.text` … and `.data` … sections of the original ELF file", `.bss` occupies no file space and its memory size is `p_memsz - p_filesz`, and the trailing bytes are "the relocation entries, usually from the `.rel.text` and/or `.rel.data` sections", each a `uint32` byte offset from the segment start (`:47-53`). The counterpart in the asset container: asset entries are missing their first 16 header bytes because for those formats that region is only an ident plus compression flags, which is *why* the audio entry type grows extra fields (sample rate, sample format) to compensate (`formats/pdz.md:60`).
- **Negative control:** Mapping a container offset straight onto a section name and getting a valid-looking but meaningless disassembly.
- **Source:** `cranksters/playdate-reverse-engineering` — CC0-1.0.

---

## 3. Managed / .NET

### N-19 — In managed RE, the interesting finding is the *sink*, not the serializer
- **Practice:** When reading decompiled .NET, the defensible finding is "untrusted input reaches a deserializer whose type selection is attacker-influenced", plus the *ordering* of the guard. Guard-after-construction is not a guard.
- **Preconditions:** Decompiled source or IL where you can see both the deserialization call and the type-resolution path.
- **Pass signal:** The analysis distinguishes three sinks by their type-resolution mechanism: .NET JSON with `TypeNameHandling` / `JavaScriptTypeResolver` (a user-controlled variable selecting the type is the finding), `BinaryFormatter` (Microsoft's own guide: dangerous, cannot be secured, should not be used), and `DataContractSerializer`/`XmlSerializer` where the *type itself* comes from data (the cheat sheet's example resolves `Type.GetType(typename)` from a database value and deserialises into it). The ordering lesson is stated in one line: constructing the object first and checking `is SomeDangerousObjectType` afterwards is too late — "Execution may have already occurred."
- **Negative control:** Grepping for the class name and reporting "uses BinaryFormatter" with no data-flow statement. Fake shape: a hit count where a hit means nothing.
- **Boundary:** version-scoped — newer .NET targets refuse `BinaryFormatter`, so always record the target framework the assembly declares before claiming the sink is live.
- **Source:** `OWASP/CheatSheetSeries` — CC-BY-SA-4.0 — `cheatsheets/Deserialization_Cheat_Sheet.md:233-301`.

### N-20 — Opaque-box format identification: match on magic, not on "looks structured"
- **Practice:** Pre-compiled serialization formats have fixed, documented signatures. Recognizing the format from a capture is a lookup, and the lookup has a known false-positive profile.
- **Preconditions:** Raw bytes (or their base64 form) from a capture, file, or memory region.
- **Pass signal:** Exact signature match on a constant: Java serialization is `AC ED 00 05` in hex, `rO0` in base64, or `Content-type: application/x-java-serialized-object`; Python pickle output often begins `gASV` once base64'd; .NET `BinaryFormatter` payloads base64 to a stream starting `AAEAAAD/////`; JSON.NET type-tagged payloads contain `TypeObject` or `$type:` (`Deserialization_Cheat_Sheet.md:31, 82-87, 244-255`).
- **Negative control:** Assuming base64 implies one format. The cheat sheet states the precondition for its own heuristic: if the data is base64- or hex-encoded, the trailing-dot test does not hold, and you must look at the leading bytes of the decoded value instead.
- **Source:** `OWASP/CheatSheetSeries` — CC-BY-SA-4.0 — `cheatsheets/Deserialization_Cheat_Sheet.md`.

### N-21 — An obfuscated managed sample is a *puzzle about data flow*, not about the decompiler
- **Practice:** Treat "string decryption behind a VM dispatch table" as a permutation + key-derivation problem to be inverted from observed bytes, and keep the decoy in mind: a table read in storage order gives garbage.
- **Preconditions:** The key material is reachable from the artifact (a permutation table plus a runtime that indexes it), which is the c04 case.
- **Pass signal:** Feeding the recovered value back into the program and getting the program's own acceptance, with the wrong-permutation value shown to fail. `crackme-corpus/README.md:40-48` states the trap and its consequence: "c04 stores keys under an **opcode permutation** … reading the array order directly gives garbage".
- **Negative control:** The decompiled string table dumped to a file and grepped. Fake shape: a table of readable strings that no execution path ever uses.
- **Source:** station `crackme-corpus/README.md`; `icsharpcode/ILSpy` (MIT) for the decompiler side — its `Documentation/` folder is code (XML-doc providers), not prose methodology, so it is a reference, not a note source.

---

## 4. Crypto / JWT

### N-22 — A signed token is not a validated token
- **Practice:** Report signature verification and claim validation as separate results. "The signature checked" says nothing about whether the token was meant for this verifier, right now, for this purpose.
- **Preconditions:** You have the token and a key. (This is the same shape as the station's `crypto-lab` verifier matrix, which prints `checks_performed` explicitly and notes "signature checked; exp/aud/iss deliberately NOT checked".)
- **Pass signal:** The verifier's own option/argument list is quoted. In PyJWT, `verify_iss` and `verify_aud` are enabled by default but **gate checks that do nothing on their own** — a token is only checked against an expected issuer/audience when the `issuer=` / `audience=` arguments are actually passed (`cheatsheets/JSON_Web_Token_Cheat_Sheet.md:370`). RFC 8725 states the requirement as MUST-level guidance: validate all cryptographic operations, validate cryptographic inputs, validate issuer and subject, use and validate audience, do not trust received claims (§3.3-3.10).
- **Negative control:** A decode that prints the claims as pretty JSON and exits 0. Fake shape: "token is valid" from a call that only split three base64 segments.
- **Source:** `OWASP/CheatSheetSeries` (CC-BY-SA-4.0); `RFC 8725` (IETF Trust License, BCP 78) §2.1, §3.3-3.10.

### N-23 — `alg` is attacker input; the verifier's key choice must not follow it
- **Practice:** Never let the token select the verification algorithm family or the key type. Pin accepted algorithms and pin the key, then let the token's `alg` be checked *against* that pin.
- **Preconditions:** You can obtain both a legitimately signed token and the public key.
- **Pass signal:** The attack is reproducible and bounded: RFC 8725 §2.1 describes both `alg: "none"` acceptance and `RS256`→`HS256` substitution, with the concrete consequence that an RSA **public** key is used as the HMAC **shared secret** ("some libraries would try to validate the signature using HMAC-SHA256 and using the RSA public key as the HMAC shared secret"). The mitigation that closes it is an allowlist: `algorithms=["ES256"]` with a strictly typed key (OWASP JWT cheat sheet `:249-299`).
- **Negative control:** A verifier that accepts whatever `alg` the header names and picks the key type to match. Fake shape: a green check produced by a library that "validated" a token it had no business validating.
- **Boundary:** recent PyJWT mitigates part of this by detecting a MAC key that *looks like* a public key (PEM/SSH format) — so a negative result from a modern library is not evidence the deployment is safe; it is evidence that one specific shape was blocked (`:274`).
- **Source:** `RFC 8725` §2.1; `OWASP/CheatSheetSeries` (CC-BY-SA-4.0).

### N-24 — Key material named *in* the token is untrusted input
- **Practice:** `jwk`, `jku`, `x5u`, `x5c` and the selectors `kid`/`x5t`/`x5t#S256` are pointers, not trust. Anchor them: resolve the key from a trust anchor you already established, then use the header only to *choose within* it.
- **Preconditions:** A verifier that fetches or selects keys dynamically.
- **Pass signal:** The distinction is stated precisely: "`x5c` and `x5u` are usable where the certificate chain validates up to an anchor already trusted for this issuer, and `kid`, `x5t` and `x5t#S256` are the normal way to choose which key from an already configured JWKS should verify a given token. What must not happen is treating any of them as the source of trust rather than as a pointer within it" (`:313`). RFC 8725 §3.10 is the normative form ("Do Not Trust Received Claims"); §2.9 adds that claims used for lookups are injection/SSRF vectors.
- **Negative control:** A verifier that accepts the `jwk` embedded in the token. Fake shape: a token signed by a key the attacker generated, accepted because it was self-describing.
- **Also worth knowing:** `kid` reaches databases and directories, so it is an injection vector on the way to the lookup (`:319`).
- **Source:** `OWASP/CheatSheetSeries` (CC-BY-SA-4.0); `RFC 8725` §2.9, §3.10.

### N-25 — Cross-JWT and audience confusion are two different checks
- **Practice:** Split the confusion cases: (a) **audience** — a token minted for service A replayed at service B that trusts the same issuer; (b) **issuer** — a token from a different issuer the verifier also trusts, where comparing `iss` alone is insufficient because the key is resolved independently of `iss`; (c) **cross-JWT type** — an ID/reset token accepted as an access token.
- **Preconditions:** Multi-service or multi-issuer token deployments; the claim being optional matters.
- **Pass signal:** Three distinct mitigations that do not substitute for each other: require your own identifier in `aud` (string or array); resolve the key set **from the validated `iss`** ("never verify against a union of keys from several issuers"); and enforce explicit typing with `typ` — or, where typing cannot be enforced, use mutually exclusive validation rules (separate signing keys, disjoint required claims, strict `iss`/`aud` isolation). The cheat sheet also records the key-order trap behind issuer confusion: a verifier that looks up by `kid` across the union of trusted JWK Sets accepts a token whose `iss` and `aud` both say what the verifier expects while `kid` selected a key from a different issuer (`:335`).
- **Negative control:** Checking `iss` only. Fake shape: a partner-tenant token accepted because the string matched, with the wrong issuer's key having done the verifying.
- **Boundary:** RFC 7519 makes `iss` and `aud` optional, so "reject tokens missing them" is a *deployment decision*, not a spec requirement — but a verifier with no `iss` has nothing to bind a key to (`:342`).
- **Source:** `OWASP/CheatSheetSeries` (CC-BY-SA-4.0); `RFC 8725` §2.7, §2.8, §3.8, §3.9, §3.11, §3.12.

### N-26 — Key/secret hygiene is a finding with observable thresholds
- **Practice:** When you hold a signing secret, report its *properties* with numbers, not adjectives: length, entropy source, reuse across audiences/issuers/purposes.
- **Preconditions:** Access to the secret (authorized test material, or a lab fixture).
- **Pass signal:** Quantitative rules: the secret must be at least the size of the algorithm output (256/384/512 bits for HS256/384/512) and at least 160 bits of entropy; it must come from a cryptographically secure local generator; it must not be a password, must not be reused across audiences or issuers, and must not be shared with an encryption purpose (`:136-183`). The cheat sheet's "invalid" list is a ready-made negative control list for a review.
- **Negative control:** `random.randbytes(32)` labelled "random secret" — a real weakness that looks like a best practice in code review.
- **Also:** on embedded targets, ECDSA generation can itself be the weakness unless deterministic ECDSA (RFC 6979) is used (`:127`).
- **Source:** `OWASP/CheatSheetSeries` (CC-BY-SA-4.0).

---

## 5. Network / protocol

*(Core pipeline in N-11/N-12/N-13. Additions:)*

### N-27 — Interception changes the trust boundary; record what the target can still see
- **Practice:** Any interception step (proxy, redirect, hook) is a claim about what the endpoint observes. Enumerate the residual observables — TLS/ALPN, cert chain, header order, header casing, HTTP/2 vs 1.1, cookie/domain scoping — because a gate can validate the body and still leak in the transport, or reject a request purely on transport shape.
- **Preconditions:** A target under test that the station hosts or is authorized to test.
- **Pass signal:** An explicit "what the target sees of us" section, which is exactly how `web-reverse/README.md` and `net-reverse/README.md` are organized. Transport shape is a *separate* attack surface from payload logic: this is why the station's web lane records the signature headers, the body, and the XHR tap as three distinct observations.
- **Negative control:** A request that succeeds through the proxy and fails when the client is native (or vice versa) with no analysis of the difference. Fake shape: "the gate is the only thing checking this" when a proxy-level difference is equally decisive.
- **Source:** station `web-reverse/README.md`, `net-reverse/README.md`; technique pattern from `0xMH/fichero-printer` `docs/PROTOCOL.md` (no license).

### N-28 — Document the message *sequence*, with the waits and the failure states
- **Practice:** A protocol is a program whose control flow is over the wire. Document ordered steps with the device-specific variants, the required settle/handshake bytes, and the timeout.
- **Preconditions:** A successful end-to-end exchange observed once, end to end.
- **Pass signal:** A step list with the literal handshake bytes, the class-specific commands, and the completion condition — Fichero's print sequence is steps 1-7 including a 12-null-byte wake-up, an AiYin-specific enable, the raster header, form feed, stop, and "wait for `0xAA` or `"OK"` (60s timeout)" (`docs/PROTOCOL.md:91-111`). The class-specificity caveat is stated as a hard requirement, not a footnote.
- **Negative control:** The sequence without the wake-up or the enable step. Fake shape: every command individually returns "OK" and nothing ever prints — the silent-accept failure again, which is why the pass signal is the *end-to-end effect*, not the per-command acknowledgements.
- **Source:** `0xMH/fichero-printer` — no license.

---

## 6. Forensics / memory

*(N-06 and N-07 carry most of the weight. Additions:)*

### N-29 — Symbol/offset correctness is a precondition of every memory finding
- **Practice:** A memory plugin's output is only as good as the kernel/debug symbols and the OS build it was given. Establish both, and treat "plugin ran" and "plugin was meaningful" as separate claims.
- **Preconditions:** A real acquisition, the matching OS build, and a usable symbol pack.
- **Pass signal:** The acquisition chain is stated: Windows symbol tables that are not cached are "queried, downloaded, generated and cached"; Mac and Linux symbol tables "must be manually produced by a tool such as `dwarf2json`"; packs ship with SHA256/SHA1/MD5 checksum files to verify download integrity; the first run on new symbols must update the cache and takes time (`README.md:64-89`).
- **Negative control:** A process list or handle table printed from an image whose kernel layer was guessed. Fake shape: a plausible-looking PEB walk that produced no error and no threads.
- **Boundary:** Linux is explicitly the weak case — kernels are trivially distinguishable-by-build, so symbol packs "cannot easily be supplied" exhaustively (`README.md:89`). Linux memory findings on this station are therefore *technique* demonstrations, not product findings, until a matching vmlinux exists.
- **Source:** `VolatilityFoundation/volatility3` — VSL-1.0 — `README.md`; station `forensics-lab/README.md`.

### N-30 — Tool agreement is not source independence
- **Practice:** When two tools report the same artifact, check whether they are independent. Two front-ends over one parser, or two plugins reading one field, are one source.
- **Preconditions:** A correlation table across tools.
- **Pass signal:** The station's `forensics-lab/README.md` carries a section titled exactly "Correlation: tool agreement is not source independence", and its triage tool "implements the same plugin *techniques* against a container that can actually be generated, and the README says which is which".
- **Negative control:** "Three tools agree" as a confidence multiplier when all three read the same underlying field. Fake shape: an artifact with one source and three witnesses.
- **Source:** station `forensics-lab/README.md`.

---

## 7. Mobile / Android

### N-31 — Establish the ceiling before analysing under it
- **Practice:** On a device/emulator lane, state what the environment can and cannot prove *before* reporting findings from it. A substituted `.so`, a stubbed return value, or an attestation check that is merely *observed* is not a working bypass, and must never be written up as one.
- **Preconditions:** Static analysis plus a dynamic harness whose fidelity you control.
- **Pass signal:** The station's `mobile-lab/README.md` has the sections "What the Frida emulator does and does not prove" and "The `.so` substitution, stated plainly", and it declines to generalize: the loop's oracle is a pyelftools check, and the README lists the ceiling rather than implying it away.
- **Negative control:** A Frida script that returns the "success" value and a screenshot. Fake shape: a bypass claim resting on a substituted library that would not load on a real device.
- **Source:** station `mobile-lab/README.md`, `mobile-lab/pinning.md`.

### N-32 — Server-verified attestation is a boundary, and we stop at it
- **Practice:** When an app's integrity story is attestation-based, the *verdict* is produced server-side. The defensible analysis is: which attestation API, which verdict fields are checked, and what the client does on failure. Circumventing attestation is out of scope for this station.
- **Preconditions:** An authorized, self-owned or station-built app, or a static reading of a third-party app's attestation *usage* (not its defeat).
- **Pass signal:** Correct, current API identification and the lifecycle facts. The OWASP mobile cheat sheet records that SafetyNet Attestation was "fully turned down in January 2025" and that all developers must migrate to the Play Integrity API, whose pattern is "obtain an integrity verdict from the device, **validate server-side**, and take action if integrity checks fail" (`:275-280`); on Apple platforms the analogue is App Attest (iOS 14+) with server-side assertion verification, complemented by DeviceCheck (`:388-391`). The version currency is itself the finding: an app still calling a turned-down API is reporting stale security posture.
- **Negative control:** A local hook that fakes a verdict. Fake shape: a client-side "pass" that the real server would reject — the mobile twin of the silent-accept failure.
- **Red line:** no bypass technique, no Play Integrity hook, no pinning-strip recipe. Recorded as existing, deliberately not developed.
- **Source:** `OWASP/CheatSheetSeries` — CC-BY-SA-4.0 — `cheatsheets/Mobile_Application_Security_Cheat_Sheet.md:275-280, 388-391`.

---

## 8. Web / JavaScript

### N-33 — Prove the algorithm with a recomputation ladder, not with "it worked"
- **Practice:** When you recover a client-side signing scheme, escalate through three requests and record three different verdicts: verbatim copy (must be **rejected**), recomputed signature (must be **accepted**), forged body (accepted only if you also recovered the key).
- **Preconditions:** A self-hosted loopback target that the station controls, and a signature gate that actually gates.
- **Pass signal:** Three distinct server responses. The station's `web-reverse/README.md` runs exactly this: a negative control without the signature headers returns `HTTP 401 {"ok":false,"error":"missing-signature-headers"}`; a captured request returns `200` with `x-lab-ts` / `x-lab-sign` and body; replay of a verbatim copy returns `409 replayed-signature` ("a copy is worthless"); a recomputed signature returns `200 accepted` ("the algorithm was recovered"); a forged body returns `200 accepted` ("the client's powers are now ours"). The key derivation is independently cross-checked: `sha256(key)[0:16] == the server's keyId`.
- **Negative control:** Sending a modified body with the original signature and calling it success because the response was 200. Fake shape: a gate that validates presence, not binding.
- **Why this is the transferable form:** the ladder separates three claims that are usually collapsed — "I can send a valid request" (trivially true with a copy), "I can compute the signature" (algorithm recovered), "I can sign arbitrary content" (key recovered). Only the last is a real capability.
- **Source:** station `web-reverse/README.md`.

### N-34 — Use the protocol as the contract, and the browser as the observation device
- **Preconditions / Pass signal:** Same shape as the station lane. Reference for exact field names when scripting a capture: the Chrome DevTools Protocol JSON definition is the authoritative schema for `Network`/`Runtime`/`Page` domains (BSD-3-Clause, 1.5k★) — cite it rather than guessing parameter names.
- **Negative control:** Parsing a page with regex/string search and calling the result a recovery when the value is computed at runtime. Fake shape: a "recovered key" that is a string literal in the bundle and never used.
- **Source:** `ChromeDevTools/devtools-protocol` — BSD-3-Clause (reference only, not read line-by-line in this pass); station `web-reverse/README.md`.

---

## 9. Fuzzing / differential analysis

### N-35 — Refactor the input path before you fuzz it
- **Practice:** A fuzzer's reach is a property of the harness, not of the target. Cut everything between the byte stream and the logic under test.
- **Preconditions:** You have the target, ideally the source.
- **Pass signal:** Documented mechanical transformations: for a **network service**, fuzzing over the socket is "inadequate" on three counts (10-20× slowdown, no scaling, and stateful protocols need back-and-forth packet interplay which coverage-aware fuzzers mostly do not support) — the established fix is to change the source to read from a file or stdin (fd 0), optionally shared memory plus persistent mode, which is "a performance gain of x10 instead of a performance loss of over x10 — that is a x100 difference" (`docs/best_practices.md:64-85`). For a **GUI**, the guidance is the same: if the program can read the test case from a file/fixed path/env var without interaction it is suitable, otherwise write a new `main()` that reads the test case and calls the processing function directly, because "the GUI functionality is a huge CPU/time overhead" (`:49-62`).
- **Negative control:** Fuzzing a service over a loopback socket for a day and reporting "no crashes" from a harness that spent its budget in `recv()`.
- **Source:** `AFLplusplus/AFLplusplus` — AGPL-3.0 — `docs/best_practices.md`.

### N-36 — Seed corpus and trim semantics
- **Practice:** Seed with inputs that already reach the parser; understand that the fuzzer's `trim` stage minimizes a case to the shortest input that preserves measured behavior, which is why a minimized crash is a *better* crash.
- **Preconditions:** A working harness (see N-35) and a coverage-instrumented build.
- **Pass signal:** Stage visibility in the status screen: `calibration` (examines the execution path for anomalies and establishes baseline speed), `trim L/S`, then the deterministic stages `bitflip`, `arith`, `interest`, `extras` (dictionary), then `havoc`, then `splice` as the last resort after a full cycle with no new paths (`docs/afl-fuzz_approach.md:208-254`). The algorithm itself is stated in six steps (load seeds → pop → trim → mutate → keep if a new transition is recorded → repeat), with a side product: "a small, self-contained corpus of interesting test cases … extremely useful for seeding other … testing regimes" (`:12-37`).
- **Negative control:** A "crash" that is a 4 MB input when 200 bytes reproduce it. Fake shape: a report citing the original test case, which the next person cannot minimise.
- **Timing expectation to state in reports:** "most fuzzing jobs should be expected to run for days or weeks; for a moderately complex project, the first pass will probably take a day or so" (`:103-106`) — and a status interpretation rule: the cycle counter colour-codes progress, magenta on the first pass → yellow while new finds continue → blue → green when it has been quiet (`:139-143`).
- **Source:** `AFLplusplus/AFLplusplus` — AGPL-3.0.

### N-37 — Instrument-list discipline: only exclude code that does not touch the data
- **Practice:** When restricting instrumentation, deny-list by "does this function process fuzz data directly or indirectly", not by "is this function noisy".
- **Preconditions:** `afl-clang-fast` PCGUARD or `afl-clang-lto` instrumentation (the doc is explicit that the identification procedure is "effectively possible only with" these).
- **Pass signal:** The stated rule: "Only exclude those functions from instrumentation that provide no value for coverage — that is if it does not process any fuzz data directly or indirectly (e.g., hash maps, thread management etc.). If … a function directly or indirectly handles fuzz data, then you should not put the function in a deny instrumentation list and rather live with the instability" (`docs/best_practices.md:194-198`). Unstable edges are attributable: run with `AFL_DEBUG=1` and read the offending edge IDs from the `var_bytes` entry in `out/fuzzer_stats`, then map IDs to functions via the compile-time ID document (`:151-179`).
- **Negative control:** Deny-listing a parser because it also initializes a hash map, then reporting the coverage drop as a property of the parser.
- **Source:** `AFLplusplus/AFLplusplus` — AGPL-3.0 — `docs/best_practices.md`.

### N-38 — Reproduction is a deliverable, and it is checked by a second execution
- **Practice:** A found bug ships with the exact testcase plus the exact command; verify by re-running that command, not by re-reading the crash log.
- **Preconditions:** A crash artifact on disk.
- **Pass signal:** The command form is the pass condition: `gdb --args /out/$PROJECT/$FUZZ_TARGET /out/$PROJECT/testcase` — the testcase is copied to the host output directory so the *same path* is used in the image (`google/oss-fuzz/docs/advanced-topics/debugging.md:29-39`). Also record the honest limitation of the debug image: it has no access to your sources, so source-level debugging requires integrating the target upstream (`:39-45`).
- **Negative control:** A crash report with the sanitizer's stack trace and no testcase file. Fake shape: an unreproducible "crash" that nobody can re-run.
- **Source:** `google/oss-fuzz` — Apache-2.0 — `docs/advanced-topics/debugging.md`.

---

## 10. Source ledger

All read on **2026-09-30** via `gh api` (metadata) and shallow/sparse clones into
`%TEMP%\re-research\KnowledgeBase\` (outside both repos).

| # | Source | License (verified file) | What I actually read |
|---|---|---|---|
| S1 | `cranksters/playdate-reverse-engineering` | CC0-1.0 | `readme.md`, `formats/luac.md`, `formats/pdex.md`, `formats/pdz.md` |
| S2 | `0xMH/fichero-printer` | **no LICENSE file** (GitHub API: NOASSERTION) | `docs/PROTOCOL.md` (191 lines, complete) |
| S3 | `techge/PRE-list` | CC0-1.0 | `README.md` (423 lines: overview matrix, input/output matrix, tested protocols, references) |
| S4 | `netzob/netzob` | GPL-3.0 (`COPYING.txt`) | `doc/documentation/source/tutorials/discover_features.rst` |
| S5 | `mandiant/capa` | Apache-2.0 | `doc/limitations.md`, `doc/rules.md`, `tests/fixtures/features/README.md`, `README.md` (head) |
| S6 | `mandiant/capa-rules` | Apache-2.0 | `README.md`, `doc/format.md` (grepped: examples/nursery/lib/scope) |
| S7 | `AFLplusplus/AFLplusplus` | **AGPL-3.0** (`LICENSE`) | `docs/best_practices.md`, `docs/afl-fuzz_approach.md` |
| S8 | `google/oss-fuzz` | Apache-2.0 | `docs/advanced-topics/code_coverage.md`, `docs/advanced-topics/debugging.md` |
| S9 | `VolatilityFoundation/volatility3` | VSL-1.0, non-commercial (NOASSERTION) | `README.md` |
| S10 | `OWASP/CheatSheetSeries` | CC-BY-SA-4.0 | `JSON_Web_Token_Cheat_Sheet.md` (546), `Deserialization_Cheat_Sheet.md` (386), grep of `Mobile_Application_Security_Cheat_Sheet.md` |
| S11 | `RFC 8725` — JSON Web Token Best Current Practices | IETF Trust License (BCP 78); freely readable at rfc-editor.org | §1-2.9 verbatim reader output |
| S12 | `mandiant/flare-ida` | Apache-2.0 | `README.md` |
| S13 | `SigmaHQ/sigma` | mixed / NOASSERTION | `rules-compliance/README.md` — content is literally "TBD"; **low yield, see §11** |
| S14 | `OWASP/mastg` | CC-BY-SA-4.0 | root/`best-practices`/`knowledge` listing + heading grep. **Superseded**: this tree is the legacy MASTG v1 content; the current MASTG v2 test cases are not present in the default branch |

Station-internal sources (no license question, already committed): `crackme-corpus/README.md`,
`web-reverse/README.md`, `crypto-lab/README.md`, `net-reverse/README.md`,
`forensics-lab/README.md`, `managed-lab/README.md` + `IL-READING.md`, `mobile-lab/README.md`
+ `pinning.md`, `headless-lab/README.md`.

**Reference-only (license known, not read this pass):** `ChromeDevTools/devtools-protocol`
(BSD-3-Clause), `icsharpcode/ILSpy` (MIT), `VirusTotal/yara` (BSD-3-Clause),
`mandiant/flare-vm` (Apache-2.0), `OWASP/owasp-mastg` (same tree as S14).

---

## 11. Deliberately skipped

**Named by the Owner but nonexistent (HTTP 404 on `gh api repos/…`, and no search hit):**
- `sw33tn0n/bl0gger` — gone; only unrelated forks exist. Nothing to read, nothing skipped on policy.
- `0xEA01/Guide-to-Windows-Privilege-Escalation` — gone.
- `0x727/Bootstrap` — gone.
- `carlospolack/SEC-EDGAR` — no such user or repo; the only SEC-EDGAR hits are financial-scraping
  tools. **Skipped as irrelevant**, not merely missing.
- `SecureIQLab` notes collections — the two surviving repos are an empty `www` tree and a
  GitHub-Pages stub, 0 stars, no license, no content. **Skipped: no substantive material.**
- `nationalsecurityagency/ghidra-class` — does not exist as a repo; the Ghidra repo's
  `Ghidra/Features/Base/docs` path is absent in the current tree, so **no prose Ghidra
  methodology was quotable** this pass. This is a real gap in the corpus (see §12).

**Skipped for licensing / redistribution risk:**
- `danafaye/WindowsAPIAbuseAtlas` (174★) — "a living guide to lesser-known and **evasive**
  Windows API abuses used in malware, **with practical PoCs**". Exists; **excluded from what we
  adopt** per the red line on offensive tooling. Recorded as existing, **not summarized** and
  not opened further.
- Any pirated copy of *Practical Reverse Engineering* or *Practical Malware Analysis*.
  The book is cited by name only; the freely-licensed artifacts we actually read are
  `capa-rules`' public `examples:` entries and the `baderj/practical-reverse-engineering`
  exercise-solution repos (not cloned, not used).
- `sw33tn0n/PayloadsAllTheThings` (MIT, but pure payload/exploit content) — **not opened,
  not adopted.**

**Skipped as low-yield after inspection:**
- `leoetlino/botw-re-notes` (109★, no license, 251 MB) — cloned, then abandoned: game-specific
  and no method transferable to our domains. Not read.
- `SigmaHQ/sigma` `rules-compliance/` — the promising "rules that check rules" idea is
  present as a directory, but the README is "TBD". Recorded, not mined.
- `ChromeDevTools/devtools-protocol` JSON — cited the schema by reference only; the protocol
  JSON was not read end to end.

**Red-line boundaries taken while reading:**
- N-10 notes that a container flag selects encryption used as DRM. Recorded as existing; no
  method for defeating it was sought, found, or written.
- N-32 records Play Integrity / App Attest as a server-side boundary. No bypass technique,
  hook recipe, or attestation-patching method was collected, and the note is written so it
  cannot be read as one.

---

## 12. Gaps this pass did not close

1. **No prose Ghidra methodology.** The NSA Ghidra training textbook is not in the current
   `nationalsecurityagency/ghidra` tree. Next step: the Ghidra *User Guide* site source
   (`ghi-doc`/`ghidra_docs` on GitHub) — worth a dedicated pass.
2. **No .NET decompiler-limitation notes.** ILSpy's `Documentation/` folder is code, not prose.
   The equivalent of N-01 for managed code ("decompiler output is a hypothesis; check the IL
   when control flow looks impossible") is currently unsupported by an external citation.
3. **No Brendan Gregg / DTrace / BPF material read.** Still to be harvested for the
   "observe the running system at syscall granularity" lane, which is the natural external
   counterpart to our native headless lane.
4. **No academic PRE primary text read** — S3 is a bibliography; §2.9 of that list (tracing
   over execution vs. network) is unread. NetPlier (NDSS 2021) is the strongest lead.
5. **Memory-forensics artifact knowledge** is thin: N-06/N-29/N-30 rest on one README plus our
   own lab notes. Windows-artifact references (Amcache/Prefetch/SRUM) have no external citation
   in this corpus yet.

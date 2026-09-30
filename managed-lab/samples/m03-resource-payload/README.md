# m03 — resource-embedded payload

**Technique.** A payload that is base64 inside a file that is itself an embedded
resource inside the assembly, with one position-dependent XOR on top whose seed is
derived from the resource name's length (`0x5A ^ (name.Length & 0x3F)`). Nothing in
the metadata or the user strings names the contents.

**Two skills, and they are different.** Getting the *bytes* is an `ilspycmd`
operation with no C# equivalent:

```powershell
ilspycmd --list-resources out\m03\m03_resource.dll
ilspycmd --resource M03.ResourcePayload.payload.b64 -o out\m03\extracted out\m03\m03_resource.dll
```

Reading the *bytes* is reading the loader. The solver does both: it takes the
suffix from the decompiled `ResourceSuffix` const, the seed by evaluating the
decompiled expression with the name substituted, and the mask by taking the
assignment inside the loop verbatim.

**The trap.** Stopping after step 2. The bytes are in hand and still masked.
`solve-m03.mjs --skip-mask` is that, and it produces 117 bytes of noise.

**Known answer.**

```
resource  M03.ResourcePayload.payload.b64
length    117
magic     M03P
version   0x02
sha256    ae5ee44b7f198f47106fd52f1d17f72e804144598480c90ebe302d53d1300f24
body      {"name":"stage2","ver":"1.4.3","offset":"0x2A","note":"resource payload recovered without executing the loader"}
```

**Loop placement.** TRIAGE (`--list-resources` finds the payload without
decompiling) → NARROW (the loader is the only consumer) → VERIFY (sha256 and
fields compared against the sample's own output).

**Skill.** Resource extraction and loader re-implementation, which together are
the managed equivalent of unpacking a section.

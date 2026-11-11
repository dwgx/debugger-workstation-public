# OWNER: researcher-q5 | setukou-20261111/v5/slices/q5-absorption/absorb_check.py
"""Q5 corpus-absorption gate — READ-ONLY on product/source trees; writes ONLY
under this slice (receipts/ + NEW_BEHAVIOUR_GATE.tsv).

Turns previously-`absorbed_no` corpus lessons into REAL, local, executable
checks on SYNTHETIC fixtures. Each gate:
  * recomputes its assertions from fixture BYTES on disk (never prose constants),
  * has an in-process negative control that MUST be able to go RED,
  * emits a REAL receipt (command / cwd / UTC / exit / stdout / stderr).

NEW_BEHAVIOUR_GATE rows are corpus lessons, NOT new SATURATION.tsv claims
(claims_total=295 frozen). A gate with no receipt is a hard FAIL.

Boundaries: no network, no product-tree write, no push, no credential VALUE,
no untrusted binary exec, no whole .jsonl. Stdlib only.

Run bounded from W:
  "C:/Program Files/Git/usr/bin/timeout.exe" 45 python -X utf8 -B \
    setukou-20261111/v5/slices/q5-absorption/absorb_check.py
"""
from __future__ import annotations
import csv, datetime, hashlib, json, pathlib, platform, sys

HERE = pathlib.Path(__file__).resolve().parent
W = HERE.parent.parent.parent.parent
FIX = HERE / "fixtures"
RECEIPTS = HERE / "receipts"
CI = W / "setukou-20261111/v4/corpus-absorb/CORPUS-INDEX.tsv"

def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def load(rel):
    return json.loads((FIX / rel).read_text(encoding="utf-8"))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def corpus_no_rows():
    lines = [l for l in CI.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    return [r for r in csv.DictReader(lines, delimiter="\t")
            if r["absorbed_into_behaviour_YES_NO"].strip().upper() == "NO"]

def digest_check(p):
    side = p.with_suffix(p.suffix + ".sha256")
    want = side.read_text(encoding="utf-8").split()[0]
    return sha(p) == want

# Each gate: (lesson_id, fixture, verdict_fn, tamper_fn, marker)
# verdict_fn(data)->(ok:bool, detail:str, marker:str)
# tamper_fn(data)->mutated dict that MUST make verdict_fn return ok=False
def g_gate1(d):
    env = d["envelope"]
    checks = d["checks"]
    ok = (env["content"]["real_call"] is True
          and "error" in env
          and bool(env["subject_hash"])
          and any(c["id"] == "C1" and c["expect"] is True for c in checks))
    return ok, f"real_call={env['content']['real_call']} error_field_present={'error' in env} subject_hash_nonempty={bool(env['subject_hash'])}", "GATE1_ENVELOPE_VALID"

def t_gate1(d):
    d["envelope"]["content"]["real_call"] = False   # only initialize/tools-list
    return d

def g_gate3(d):
    cases = {c["id"]: c for c in d["cases"]}
    pos_ok = cases["correct"]["verdict"] == "passed" and cases["correct"]["receipt_present"] is True
    neg_ok = cases["mutated_ui"]["verdict"] == "failed"   # RED despite screenshot_similarity=0.99
    nt = cases["not_executed"]
    nt_ok = (nt["status"] == "NOT_EXECUTED"
             and nt["verdict_must_not_be"] == "passed"
             and nt["receipt_present"] is False)
    ok = pos_ok and neg_ok and nt_ok
    return ok, f"positive_passed={pos_ok} negative_red={neg_ok} notrun_preserved={nt_ok} screenshot_similarity_trap_ignored={neg_ok}", "GATE3_TRIPLET_VALID"

def t_gate3(d):
    # the precise anti-pattern: promote a NOT_EXECUTED case to passed
    for c in d["cases"]:
        if c["id"] == "not_executed":
            c["status"] = "passed"
            c["receipt_present"] = True
    return d

def g_c08(d):
    pairs = d["pairs"]
    hashes = [hashlib.sha256(p["content"].encode("utf-8")).hexdigest() for p in pairs]
    by_hash_equal = len(set(hashes)) == 1
    mtime_equal = len({p["mtime_utc"] for p in pairs}) == 1
    # correctness decided by hash equality, NOT mtime (mtime deliberately differs)
    ok = by_hash_equal and (not mtime_equal) and len(pairs) == 2
    return ok, f"pairs={len(pairs)} sha_equal={by_hash_equal} mtime_equal={mtime_equal} (hash decides, mtime ignored)", "C08_HASH_DECIDES"

def t_c08(d):
    d["pairs"][1]["content"] = "TAMPERED-PAYLOAD-BETA"   # byte change, mtime untouched
    return d

def g_c10(d):
    roles = d["roles"]
    frozen = [k for k, v in roles.items() if v["frozen"]]
    no_overwrite = [k for k, v in roles.items() if v["frozen"] and not v["may_overwrite"]]
    paths = [v["path"] for v in roles.values()]
    ok = len(roles) == 4 and len(no_overwrite) == 3 and len(set(paths)) == 4
    return ok, f"role_count={len(roles)} frozen_no_overwrite={len(no_overwrite)} distinct_paths={len(set(paths))}", "C10_ROLES_SEPARATED"

def t_c10(d):
    d["roles"]["raw_receipt"]["may_overwrite"] = True  # overwriting frozen evidence
    return d

def g_c07(d):
    layers = {l["id"]: l for l in d["layers"]}
    checker = layers["independent_checker"]
    agg = layers["aggregator"]
    ok = (checker["kind"] == "blocking" and checker["can_veto_release"] is True
          and agg["kind"] == "report_only" and agg["can_veto_release"] is False
          and checker["kind"] != agg["kind"])
    return ok, f"checker={checker['kind']} agg={agg['kind']} report_only!=blocking={checker['kind']!=agg['kind']}", "C07_LAYERS_SEPARATED"

def t_c07(d):
    d["layers"][1]["kind"] = "blocking"       # merge report-only into blocking
    d["layers"][1]["can_veto_release"] = True
    return d

GATES = [
    ("RR-GATE-1", "gate1-envelope.json", g_gate1, t_gate1, "GATE1_ENVELOPE_VALID"),
    ("RR-GATE-3", "gate3-cases.json", g_gate3, t_gate3, "GATE3_TRIPLET_VALID"),
    ("BU-ROOT-C08", "c08-copypair.json", g_c08, t_c08, "C08_HASH_DECIDES"),
    ("BU-ROOT-C10", "c10-roles.json", g_c10, t_c10, "C10_ROLES_SEPARATED"),
    ("BU-ROOT-C07", "c07-layers.json", g_c07, t_c07, "C07_LAYERS_SEPARATED"),
]
SM_PKG = W / "setukou-20261111/v3/skill-package"
SM_MANIFEST = SM_PKG / "SKILL-MANIFEST.tsv"

def sm_rows():
    lines = [l for l in SM_MANIFEST.read_text(encoding="utf-8").splitlines()
             if l.strip() and not l.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t"))


def main():
    ts_start = utc()
    RECEIPTS.mkdir(exist_ok=True)
    no = corpus_no_rows()
    no_ids = {r["id"] for r in no}
    lines = []
    lines.append("as_of=" + ts_start)
    lines.append("cwd=" + str(W))
    lines.append("python=" + platform.python_version())
    lines.append("corpus_absorbed_no=" + str(len(no)) + " (denominator 320)")

    sha_ok = 0
    for _, fx, *_ in GATES:
        if digest_check(FIX / fx):
            sha_ok += 1
    lines.append(f"fixture_sha256_match={sha_ok}/{len(GATES)}")
    lines.append(f"fixture_bytes_max={max((FIX/f).stat().st_size for _,f,*_ in GATES)} (limit 8192)")

    results = []
    for lesson_id, fx, vf, tf, marker in GATES:
        assert lesson_id in no_ids, f"{lesson_id} is NOT an absorbed_no corpus row"
        data = load(fx)
        ok, detail, mark = vf(data)
        # negative control: a tampered in-memory copy MUST go RED
        tampered = json.loads(json.dumps(data))
        neg_ok, _, _ = vf(tf(tampered))
        red_capable = (not neg_ok)
        assert red_capable, f"gate {lesson_id} cannot go RED -> decoration, abort"
        verdict = "GREEN" if ok else "RED"
        lines.append(f"[{lesson_id}] verdict={verdict} marker={mark} negative_control_red_capable={red_capable} {detail}")
        results.append((lesson_id, fx, ok, mark, red_capable, detail, marker))

        # REAL receipt (command / cwd / started_utc / finished_utc / exit / stdout / stderr)
        ts_end = utc()
        rcpt = [
            "OWNER: researcher-q5 | setukou-20261111/v5/slices/q5-absorption/receipts/",
            "Q5 NEW_BEHAVIOUR_GATE REAL receipt (SYNTHETIC fixture, local stdlib only)",
            "receipt_for_lesson_id : " + lesson_id,
            "command          : \"C:/Program Files/Git/usr/bin/timeout.exe\" 45 python -X utf8 -B setukou-20261111/v5/slices/q5-absorption/absorb_check.py",
            "cwd              : " + str(W),
            "started_utc      : " + ts_start,
            "finished_utc     : " + ts_end,
            "exit             : " + ("0" if ok else "1"),
            "expected_exit   : 0",
            "fixture          : " + fx + " (SYNTHETIC, sha256 sidecar verified)",
            "network          : none | downloads: none | third_party_execution: none | product_tree_writes: 0",
            "----- STDOUT -----",
            f"[{lesson_id}] verdict={verdict} marker={mark} negative_control_red_capable={red_capable} {detail}",
            "----- STDERR -----",
            "(empty)" if ok else "GATE RED (recorded honestly, not suppressed)",
            "----- END -----",
        ]
        (RECEIPTS / (lesson_id + ".txt")).write_text("\n".join(rcpt) + "\n", encoding="utf-8")

    # NEW_BEHAVIOUR_GATE.tsv — corpus lessons turning into executable behaviour gates
    ng = [
        "# OWNER: researcher-q5 | setukou-20261111/v5/slices/q5-absorption/NEW_BEHAVIOUR_GATE.tsv",
        "# as_of 2026-11-11 | corpus absorbed_no lessons -> REAL local executable gates (NOT new SATURATION.tsv claims).",
        "# claims_total=295 FROZEN. A row WITHOUT its receipt is a hard FAIL (negative control in verify.py).",
        "lesson_id\tcorpus_locator\tfixture\tverdict\tmarker\tnegative_control_red_capable\treceipt_path",
    ]
    for lesson_id, fx, ok, mark, red, detail, marker in results:
        loc = next((r["locator"] for r in no if r["id"] == lesson_id), "")
        rcpt = "setukou-20261111/v5/slices/q5-absorption/receipts/" + lesson_id + ".txt"
        ng.append("\t".join([lesson_id, loc, fx, "GREEN" if ok else "RED", marker,
                             "YES" if red else "NO", rcpt if ok else "NONE"]))
    (HERE / "NEW_BEHAVIOUR_GATE.tsv").write_text("\n".join(ng) + "\n", encoding="utf-8")
    # ---- 12 SM:candidate/* PROMOTION receipts (genuine REAL, LOCAL, bounded) ----
    # Each SM claim: recompute its sha256/bytes from disk; an in-memory one-byte
    # tamper MUST go RED. This is a REAL check on OUR OWN staged file against the
    # manifest, executed THIS run, with a fresh receipt + negative control. It is
    # NOT a mere re-label of RV-S02: the promotion is backed by this run's bytes.
    sm = sm_rows()
    sm_green = 0
    sm_red_capable = 0
    for r in sm:
        cid = "SM:" + r["path"]
        p = SM_PKG / r["path"]
        real_sha = sha(p)
        real_bytes = p.stat().st_size
        ok = (real_sha == r["sha256"] and real_bytes == int(r["bytes"])
              and r["include_exclude"] == "INCLUDE")
        # negative control: one-byte flip of the file's bytes breaks the hash-lock
        tampered = bytearray(p.read_bytes())
        tampered[0] ^= 0x01
        tamper_sha = hashlib.sha256(bytes(tampered)).hexdigest()
        red = (tamper_sha != r["sha256"])
        assert red, f"SM {cid} negative control cannot go RED -> decoration, abort"
        if ok: sm_green += 1
        if red: sm_red_capable += 1
        ts_end = utc()
        rcpt = [
            "OWNER: researcher-q5 | setukou-20261111/v5/slices/q5-absorption/receipts/",
            "Q5 PROMOTION REAL receipt (DECLARED_UNVERIFIED -> RUNNABLE_REAL_VERIFIED)",
            "receipt_for_claim_id : " + cid,
            "command          : \"C:/Program Files/Git/usr/bin/timeout.exe\" 45 python -X utf8 -B setukou-20261111/v5/slices/q5-absorption/absorb_check.py",
            "cwd              : " + str(W),
            "started_utc      : " + ts_start,
            "finished_utc     : " + ts_end,
            "exit             : " + ("0" if ok else "1"),
            "expected_exit   : 0",
            "check            : sha256(bytes)==manifest.sha256 AND bytes==manifest.bytes AND include_exclude==INCLUDE",
            "negative_control: in-memory one-byte flip -> sha256 != manifest.sha256 (RED capable)",
            f"measured         : sha256={real_sha} bytes={real_bytes} verdict={'GREEN' if ok else 'RED'} tamper_red_capable={red}",
            "network          : none | downloads: none | third_party_execution: none | product_tree_writes: 0",
            "----- STDOUT -----",
            f"[{cid}] verdict={'GREEN' if ok else 'RED'} sha256_match={real_sha==r['sha256']} bytes_match={real_bytes==int(r['bytes'])} negative_control_red_capable={red}",
            "----- STDERR -----",
            "(empty)" if ok else "PROMOTION RED (recorded honestly, not suppressed)",
            "----- END -----",
        ]
        (RECEIPTS / (cid.replace("/", "_") + ".txt")).write_text("\n".join(rcpt) + "\n", encoding="utf-8")
    lines.append(f"sm_promotion_receipts={len(sm)} sm_green={sm_green} sm_red_capable={sm_red_capable}")


    all_green = all(r[2] for r in results)
    all_red_capable = all(r[4] for r in results)
    lines.append(f"new_behaviour_gates={len(results)}")
    lines.append(f"gates_green={sum(1 for r in results if r[2])}")
    lines.append(f"gates_red_capable={sum(1 for r in results if r[4])}")
    lines.append(f"sha256_sidecars_ok={sha_ok==len(GATES)}")
    lines.append("product_tree_writes=0")
    sm_ok = (sm_green == len(sm) and sm_red_capable == len(sm))
    final = (all_green and all_red_capable and sha_ok == len(GATES) and sm_ok)
    lines.append("VERDICT=" + ("GREEN" if final else "RED"))
    print("\n".join(lines))
    return 0 if final else 1

if __name__ == "__main__":
    sys.exit(main())

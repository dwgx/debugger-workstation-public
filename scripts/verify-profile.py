#!/usr/bin/env python3
"""verify-profile.py -- static diagnostics and caller-pinned bounded runner verification.

Separates three evidence layers that must never be conflated:

  integrity  : are the actual bytes on disk the bytes claimed (hash/size/containment)?
  execution  : did the required steps really run to terminal state under the exit contract?
  semantic   : does an independent, pre-frozen oracle assertion hold for the observed facts?
  negative   : inverted-polarity control proving the evaluator can fail.

Rules enforced here (05-EVIDENCE-CONTRACT.md sections 3-6, 10):
  * unknown MAJOR schema_version is never a success;
  * the required set is frozen before the run and aggregation uses it, not what arrived;
  * skipped / not_run / prereq / unsupported / unknown / interrupted / blocked never count as pass;
  * expected_exit may be nonzero and is compared, never coerced to 0;
  * a retry needs a new attempt_id with parent_attempt_id pointing at the prior failure,
    and the prior failure bytes must remain unchanged;
  * touching an old artifact's mtime without new content and without a new attempt is
    stale_not_fresh => RED (the advisor's false-fresh counterexample).

Two schema majors are dispatched from the schema's own `$id`, never from a global guess:

  run-receipt.1  LEGACY DIAGNOSTIC. Frozen 2026-11-11 demo contract, kept byte-identical
                 because prior-wave receipts are frozen evidence. It is NOT product
                 acceptance: the receipt still carries `kind`/`expected`, so a successful
                 receipt can restate its own rules. Reports print LEGACY_DIAGNOSTIC_ONLY=YES.
  run-receipt.2  STATIC DIAGNOSTIC. Every static rule lives OUTSIDE the receipt, in an
                 external anchor file (required_check_ids, per-check kind/steps/exit
                 contract, assertion payload, run/attempt inventory, self seal). The
                 receipt supplies observations only. Checked in this frozen order:
                   1 schema identity / unknown major / unsupported schema form
                   2 ID uniqueness BEFORE any dict/set (content-different same ID rejected)
                   3 anchor file bytes recomputed and bound to the receipt's declared digest
                   4 kind/steps/expected_exit taken from the anchor, never from the receipt
                   5 execution / check status / attempt terminal compatibility
                   6 artifact component-path ownership + hash/size + producer attempt
                   7 facts parsed from verified artifact bytes with a versioned parser,
                     strict types (True is not 1)
                   8 aggregation over the frozen unique required set; empty required set,
                     shrunken denominator and green JSON over a nonzero/abnormal
                     run_harness cannot pass.
  run-receipt.3  BOUNDED RUNNER PRODUCT PATH. The caller supplies a frozen plan digest;
                 the terminal binds observed subprocess state and retained raw bytes.
  `--product` requires this v3 runner path. The existing v1/v2 fixtures and
  evaluator remain static diagnostics and do not establish product execution.

Exit codes: 0 PROFILE_PASS, 1 PROFILE_FAIL, 2 PROFILE_BLOCKED, 3 PROFILE_NOT_RUN,
            4 input/usage error (receipt or oracle unreadable, schema invalid JSON).

Usage:
  python -X utf8 -B scripts/verify-profile.py \
      --schema schemas/run-receipt.v1.json \
      --receipt evidence/profile-receipts/good-pass.json \
      --oracle  evidence/profile-receipts/oracle-public-core-demo.json \
      [--artifact-root <dir>] [--json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

sys.dont_write_bytecode = True

SCHEMA_MAJOR_SUPPORTED = "run-receipt.1"  # legacy diagnostic major (frozen, not product)
PRODUCT_ACCEPTANCE_MAJOR = "run-receipt.2"  # historical static evaluator major, not a product attestation
ANCHOR_VERSION = "profile-oracle-anchor@1"
EVIDENCE_LAYERS = ("integrity", "execution", "semantic", "negative")

# Load-bearing switches for the LEGACY major. They exist so a negative control can prove
# that removing the guard changes the verdict. Product (v2) runs have no such switch:
# every guard below is unconditional.
STALE_GUARD_ENABLED = True
SKIP_COUNTS_AS_PASS = False

PASSING = frozenset({"passed"})
NONPASS = frozenset(
    {"failed", "error", "not_run", "unsupported", "unknown", "interrupted", "blocked", "skipped"}
)
INCOMPLETE = frozenset({"not_run", "unsupported", "unknown", "interrupted", "blocked", "skipped"})
VERDICT_EXIT = {
    "PROFILE_PASS": 0,
    "PROFILE_FAIL": 1,
    "PROFILE_BLOCKED": 2,
    "PROFILE_NOT_RUN": 3,
}


# --------------------------------------------------------------------------- io

def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


# ----------------------------------------------------------------- schema check
# Minimal JSON-Schema (2020-12) subset interpreter: exactly the keywords used by
# schemas/run-receipt.v1.json. Deliberately no third-party dependency.

def _type_ok(value, wanted):
    if wanted == "object":
        return isinstance(value, dict)
    if wanted == "array":
        return isinstance(value, list)
    if wanted == "string":
        return isinstance(value, str)
    if wanted == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if wanted == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if wanted == "boolean":
        return isinstance(value, bool)
    if wanted == "null":
        return value is None
    return False


def validate(instance, schema, path="$", errors=None):
    """Return a list of "path: message" strings; empty list means valid."""
    if errors is None:
        errors = []
    if not isinstance(schema, dict):
        return errors

    wanted = schema.get("type")
    if wanted is not None:
        wanted_list = wanted if isinstance(wanted, list) else [wanted]
        if not any(_type_ok(instance, w) for w in wanted_list):
            errors.append("%s: expected type %s, got %s" % (path, wanted_list, type(instance).__name__))
            return errors

    if "if" in schema:
        # Conditional subschema (draft 2020-12). Used by run-receipt.v2 for the
        # dirty=>patch/snapshot provenance rule; ignoring it would silently accept
        # "dirty candidate with no patch identity".
        probe = []
        validate(instance, schema["if"], path, probe)
        branch = schema.get("then") if not probe else schema.get("else")
        if isinstance(branch, dict):
            validate(instance, branch, path, errors)

    if "const" in schema and instance != schema["const"]:
        errors.append("%s: expected const %r" % (path, schema["const"]))
    if "enum" in schema and instance not in schema["enum"]:
        errors.append("%s: value %r not in enum %r" % (path, instance, schema["enum"]))

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append("%s: shorter than minLength %d" % (path, schema["minLength"]))
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            errors.append("%s: does not match pattern %s" % (path, schema["pattern"]))

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append("%s: below minimum %r" % (path, schema["minimum"]))
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append("%s: above maximum %r" % (path, schema["maximum"]))

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append("%s: fewer than minItems %d" % (path, schema["minItems"]))
        if schema.get("uniqueItems") is True:
            seen = {}
            for idx, item in enumerate(instance):
                token = json.dumps(item, sort_keys=True, ensure_ascii=False)
                if token in seen:
                    errors.append("%s: items %d and %d are equal but uniqueItems is true"
                                  % (path, seen[token], idx))
                else:
                    seen[token] = idx
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(instance):
                validate(item, item_schema, "%s[%d]" % (path, idx), errors)

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errors.append("%s: missing required property %r" % (path, key))
        props = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for key, value in instance.items():
            if key in props:
                validate(value, props[key], "%s.%s" % (path, key), errors)
            elif extra is False:
                errors.append("%s: additional property %r not allowed (strict)" % (path, key))
            elif isinstance(extra, dict):
                validate(value, extra, "%s.%s" % (path, key), errors)
    return errors


# ------------------------------------------------------------------- artifacts

def resolve_artifact(root, rel):
    """Component-wise containment check. Never a string prefix test (05 section 7)."""
    if not isinstance(rel, str) or not rel:
        return None
    win = PureWindowsPath(rel)
    pos = PurePosixPath(rel.replace("\\", "/"))
    if win.is_absolute() or pos.is_absolute() or win.drive or rel.startswith(("//", "\\\\")):
        return None
    if ".." in pos.parts:
        return None
    root_abs = os.path.normcase(os.path.realpath(root))
    candidate = os.path.normcase(os.path.realpath(os.path.join(root_abs, *pos.parts)))
    try:
        if os.path.commonpath([root_abs, candidate]) != root_abs:
            return None
    except ValueError:
        return None
    return candidate


def _artifact_disk_state(root, art):
    """Integrity layer: recompute from disk. Returns (ok, observed, detail)."""
    target = resolve_artifact(root, art.get("path", ""))
    if target is None:
        return False, {"resolved": False}, "artifact path outside export root or malformed"
    if not os.path.isfile(target):
        return False, {"resolved": True, "exists": False}, "artifact bytes missing on disk"
    actual_hash = sha256_file(target)
    actual_size = os.path.getsize(target)
    observed = {
        "resolved": True,
        "exists": True,
        "sha256": actual_hash,
        "size_bytes": actual_size,
        "mtime_utc": _mtime_utc(target),
    }
    if actual_hash != art.get("sha256"):
        return False, observed, "content hash mismatch"
    if actual_size != art.get("size_bytes"):
        return False, observed, "size mismatch"
    return True, observed, "bytes match declared hash and size"


def _mtime_utc(path):
    import datetime as _dt

    return _dt.datetime.fromtimestamp(os.path.getmtime(path), _dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


# ------------------------------------------------------------------ recompute

def _deep_equal(a, b):
    return json.dumps(a, sort_keys=True, ensure_ascii=False) == json.dumps(
        b, sort_keys=True, ensure_ascii=False
    )


def recompute_check(check, receipt, artifact_root, oracle=None):
    """Independently re-derive one check's status from raw observations.

    For semantic/negative checks the oracle file is the authority: the frozen
    assertion values are read from the oracle, and the receipt's own `expected`
    block must agree with them (a receipt may not relax its own expectation).

    Returns (status, detail). status None means "not recomputable from this receipt";
    the declared status is then used under the never-pass-on-skip rule.
    """
    kind = check.get("kind")
    expected = check.get("expected") or {}
    observed = check.get("observed") or {}
    frozen = ((oracle or {}).get("checks") or {}).get(check.get("id"))

    if kind == "integrity":
        art_path = expected.get("artifact")
        art = next((a for a in receipt.get("artifacts", []) if a.get("path") == art_path), None)
        if art is None:
            return "failed", "integrity check names an artifact absent from artifacts[]"
        ok, disk, detail = _artifact_disk_state(artifact_root, art)
        if not ok:
            return "failed", detail
        if expected.get("sha256") and expected["sha256"] != disk["sha256"]:
            return "failed", "expected hash does not match recomputed hash"
        if expected.get("size_bytes") is not None and expected["size_bytes"] != disk["size_bytes"]:
            return "failed", "expected size does not match recomputed size"
        return "passed", detail

    if kind == "execution":
        steps_expected = list(expected.get("steps") or [])
        steps_done = list(observed.get("completed_steps") or [])
        missing = [s for s in steps_expected if s not in steps_done]
        if missing:
            return "failed", "required steps missing terminal result: %s" % ",".join(missing)
        if observed.get("terminal_state") != "exited":
            return "failed", "terminal_state is %r, not exited" % observed.get("terminal_state")
        if observed.get("cleanup") not in (None, "converged", "not_applicable"):
            return "failed", "cleanup did not converge"
        if expected.get("backend_executed") is True and observed.get("backend_executed") is not True:
            return "failed", "backend did not execute; only evaluator/utime ran"
        exp_exit = expected.get("expected_exit")
        obs_exit = observed.get("observed_exit")
        if exp_exit is not None and obs_exit != exp_exit:
            return "failed", "exit %r != frozen expected_exit %r" % (obs_exit, exp_exit)
        if exp_exit is None:
            return "passed", "all %d required steps terminal" % len(steps_expected)
        return "passed", "all %d required steps terminal; exit %r matches frozen expected_exit" % (
            len(steps_expected),
            obs_exit,
        )

    if kind in ("semantic", "negative"):
        assertions = expected.get("assertions") or {}
        if frozen is not None:
            if not _deep_equal(assertions, frozen.get("assertions") or {}):
                return "failed", "receipt expected diverges from the pre-frozen oracle assertions"
            assertions = frozen.get("assertions") or {}
        facts = observed.get("facts") or {}
        if not assertions:
            return None, "no assertions to evaluate"
        if not facts:
            return None, "no observed facts to evaluate"
        mismatched = []
        for key, want in assertions.items():
            got = facts.get(key, "<absent>")
            if not _deep_equal(want, got):
                mismatched.append("%s expected %r got %r" % (key, want, got))
        if kind == "semantic":
            if mismatched:
                return "failed", "; ".join(mismatched)
            return "passed", "%d oracle assertions hold" % len(assertions)
        # negative polarity: the evaluator must be able to FAIL on this fact set
        if mismatched:
            return "passed", "negative control diverges as required: %s" % "; ".join(mismatched)
        return "failed", "negative control matched a value it must reject (evaluator too weak)"

    return None, "unknown check kind %r" % kind


def stale_artifacts(receipt, oracle):
    """Detect the advisor's false-fresh counterexample.

    A current-attempt artifact whose bytes equal a frozen prior attempt's bytes, with no
    backend execution, is stale even if its mtime was refreshed. Reusing a frozen
    attempt_id is also stale (no new attempt was created).
    """
    stale = []
    execution = receipt.get("execution") or {}
    attempt_id = receipt.get("attempt_id")
    prior_hashes = {a.get("sha256"): a for a in oracle.get("frozen_prior_artifacts", [])}
    frozen_attempts = set(oracle.get("frozen_attempt_ids", []))

    if attempt_id in frozen_attempts:
        stale.append({"artifact": "<attempt>", "reason": "attempt_id %r was already frozen; no new attempt" % attempt_id})

    for art in receipt.get("artifacts", []):
        prev = prior_hashes.get(art.get("sha256"))
        if prev is None:
            continue
        if art.get("attempt_id") != attempt_id:
            continue  # preserved prior bytes, not claimed as this attempt's product
        mtime_touched = (art.get("mtime_utc") or "") >= (execution.get("started_utc") or "")
        if execution.get("backend_executed") is not True and (mtime_touched or prev.get("path") == art.get("path")):
            stale.append(
                {
                    "artifact": art.get("path"),
                    "reason": "content identical to frozen prior attempt %r, backend_executed=false%s"
                    % (prev.get("attempt_id"), ", mtime refreshed" if mtime_touched else ""),
                }
            )
    return stale


def retry_problems(receipt, oracle, artifact_root):
    """Retry contract: new attempt_id, parent pointer, prior failure bytes immutable."""
    problems = []
    attempt_id = receipt.get("attempt_id")
    parent_id = receipt.get("parent_attempt_id")
    if parent_id is not None and parent_id == attempt_id:
        problems.append("retry reuses parent_attempt_id as attempt_id; a retry MUST be a new attempt")
    if parent_id is None:
        return problems

    priors = {a.get("attempt_id"): a for a in oracle.get("frozen_prior_attempts", [])}
    prior = priors.get(parent_id)
    if prior is None:
        problems.append("parent_attempt_id %r is not present in the frozen oracle; provenance unresolved" % parent_id)
        return problems
    if prior.get("outcome") != "fail":
        problems.append("parent attempt %r is not a failure record; retry chain claim unsupported" % parent_id)
    for art in prior.get("artifacts", []):
        target = resolve_artifact(artifact_root, art.get("path", ""))
        if target is None or not os.path.isfile(target):
            problems.append("prior failure artifact %r is missing; failure bytes not preserved" % art.get("path"))
            continue
        if sha256_file(target) != art.get("sha256"):
            problems.append("prior failure artifact %r bytes changed; failure record overwritten" % art.get("path"))
    return problems


# ============================================================ v2 product gate
# run-receipt.2 keeps every acceptance rule OUTSIDE the receipt:
#   schemas/run-receipt.v2.json          strict envelope; kind/expected are not receipt-owned
#   <anchor>.anchor.json (external file) required ids, per-check kind/steps/exit contract,
#                                        assertion payload, run/attempt inventory, self seal
# The receipt supplies observations only.  Each rejection below names the rule that failed;
# no rule is read from the receipt, and no guard is switchable in this path.

_SCHEMA_KEYWORDS = frozenset(
    {
        # annotations (no validation semantics)
        "$schema", "$id", "$comment", "title", "description", "default", "examples",
        # implemented assertions -- this list is the whole supported subset
        "type", "const", "enum",
        "minLength", "pattern", "minimum", "maximum",
        "minItems", "uniqueItems", "items",
        "properties", "required", "additionalProperties",
        "if", "then", "else",
    }
)
_DATA_KEYWORDS = frozenset({"const", "enum", "default", "examples"})
_SUBSCHEMA_KEYWORDS = frozenset({"items", "additionalProperties", "if", "then", "else"})
_SCHEMA_ID_RE = re.compile(r"^urn:debugger-workstation:run-receipt\.v(\d+)$")


def _unknown_keywords(schema, path="$", out=None):
    """Schema keywords this interpreter does not implement.

    Silently skipping an unknown keyword is how `false` schemas and conditional provenance
    rules become no-ops, so the v2 gate refuses the schema instead of ignoring it.
    """
    if out is None:
        out = []
    if not isinstance(schema, dict):
        return out
    for key, value in schema.items():
        if key not in _SCHEMA_KEYWORDS:
            out.append("%s.%s" % (path, key))
        elif key in _DATA_KEYWORDS:
            continue
        elif key == "properties" and isinstance(value, dict):
            for name, sub in value.items():
                _unknown_keywords(sub, "%s.properties.%s" % (path, name), out)
        elif key in _SUBSCHEMA_KEYWORDS:
            _unknown_keywords(value, "%s.%s" % (path, key), out)
    return out


def schema_identity(schema):
    """Return (major, reason). major is None when the schema form is not admissible."""
    if isinstance(schema, bool):
        return None, (
            "schema document is the JSON literal %r; a boolean schema is not an admissible "
            "product schema identity and would accept or reject everything unconditionally"
            % schema
        )
    if not isinstance(schema, dict):
        return None, "schema document is %s, not an object" % type(schema).__name__
    sid = schema.get("$id")
    if not isinstance(sid, str):
        return None, "schema document has no string $id; identity cannot be established"
    match = _SCHEMA_ID_RE.match(sid)
    if match is None:
        return None, "schema $id %r is not a recognised run-receipt identity" % sid
    unknown = _unknown_keywords(schema)
    if unknown:
        return None, "schema uses keywords this interpreter does not implement: %s" % ", ".join(unknown)
    return "run-receipt.%d" % int(match.group(1)), None


def _canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def anchor_seal(anchor):
    """sha256 over canonical JSON of the anchor with `self_sha256` removed.

    The seal is internal consistency only. The receipt's declared `anchor_sha256` binds the
    anchor FILE bytes, and the file bytes carry this seal; neither value is derived from the
    receipt's own expectations.
    """
    body = {key: value for key, value in anchor.items() if key != "self_sha256"}
    return sha256_bytes(_canonical_bytes(body))


def profile_digest(profile):
    """Identity of the frozen profile definition (id/version/platforms/capabilities)."""
    return sha256_bytes(_canonical_bytes(profile))


_PROBE_OUTPUT_TEXT = re.compile(
    r"^probe ok: imports=\[([A-Za-z0-9_.\-]*(?:, ?[A-Za-z0-9_.\-]+)*)\] entrypoint=(0x[0-9a-f]{6,16})$"
)


def parse_probe_output_text(data):
    """probe-output-text@1: one line, imports list then entrypoint. Raises ValueError."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("artifact is not UTF-8 text: %s" % exc)
    text = text.rstrip("\r\n")
    match = _PROBE_OUTPUT_TEXT.match(text)
    if match is None:
        raise ValueError("artifact does not match probe-output-text@1 grammar")
    imports = [item.strip() for item in match.group(1).split(",") if item.strip()]
    return {"imports": imports, "entrypoint": match.group(2)}


PARSERS = {"probe-output-text@1": parse_probe_output_text}

# Native runner statuses preserved verbatim by the receipt. Any of them contradicts a
# recomputed pass: SKIP/PREREQ/DRIFT/TOOL-FAULT/FLAKY never become "passed".
_NATIVE_NONPASS = frozenset(
    {"SKIP", "NOT RUN", "NOT_RUN", "PREREQ", "DRIFT", "TOOL-FAULT", "TOOL_FAULT", "FLAKY", "INTERRUPTED"}
)


def _blank_report():
    return {
        "schema_ok": False,
        "schema_errors": [],
        "schema_major_ok": False,
        "checks_total": 0,
        "checked": 0,
        "passed": 0,
        "failed": 0,
        "stale": 0,
        "skipped": 0,
        "missing_required": [],
        "layer": {name: [0, 0] for name in EVIDENCE_LAYERS},
        "check_results": [],
        "stale_detail": [],
        "retry_problems": [],
        "freeze_problems": [],
        "reasons": [],
        "verdict": "PROFILE_FAIL",
    }


def _v2_check(definition, check, receipt, anchor, artifact_root, art_by_path, terminal_problems):
    """Recompute one required check. Rules come from `definition` (frozen anchor)."""
    kind = definition["kind"]

    if kind == "integrity":
        declared = definition["artifact_path"]
        if check.get("artifact") != declared:
            return "failed", "integrity check names artifact %r, frozen definition says %r" % (
                check.get("artifact"), declared)
        art = art_by_path.get(declared)
        if art is None:
            return "failed", "integrity artifact %r is not declared in artifacts[]" % declared
        if art["sha256"] != definition["artifact_sha256"]:
            return "failed", "declared hash %s != frozen %s" % (art["sha256"], definition["artifact_sha256"])
        if art["size_bytes"] != definition["artifact_size_bytes"]:
            return "failed", "declared size %r != frozen %r" % (
                art["size_bytes"], definition["artifact_size_bytes"])
        return "passed", "bytes recomputed on disk and equal to the frozen identity"

    if kind == "execution":
        if terminal_problems:
            return "failed", "execution_not_terminal: " + "; ".join(terminal_problems)
        asserts = list(definition.get("asserts") or [])
        if not asserts:
            return "failed", "execution check asserts nothing; an empty execution contract cannot pass"
        for item in asserts:
            if item == "steps":
                continue  # required steps are covered by terminal_problems
            if item == "exit":
                observed_exit = receipt["execution"]["observed_exit"]
                if isinstance(observed_exit, bool) or not isinstance(observed_exit, int):
                    return "failed", "type_violation: observed_exit %r is not an integer (True is not 1)" % (
                        observed_exit,)
                expected_exit = anchor["execution_contract"]["expected_exit"]
                if observed_exit != expected_exit:
                    return "failed", "exit %r != frozen expected_exit %r" % (observed_exit, expected_exit)
            else:
                return "failed", "unknown execution assertion %r in frozen definition" % item
        return "passed", "single execution record satisfies %s" % ",".join(asserts)

    # semantic / negative: facts are PARSED from the verified artifact bytes.
    frozen_parser = definition.get("parser")
    if (check.get("observed") or {}).get("parser") != frozen_parser:
        return "failed", "invalid_observation: parser %r != frozen %r" % (
            (check.get("observed") or {}).get("parser"), frozen_parser)
    parser = PARSERS.get(frozen_parser)
    if parser is None:
        return "failed", "invalid_observation: parser %r is not implemented" % frozen_parser
    declared = definition["artifact_path"]
    if check.get("artifact") != declared:
        return "failed", "%s check names artifact %r, frozen definition says %r" % (
            kind, check.get("artifact"), declared)
    art = art_by_path.get(declared)
    if art is None:
        return "failed", "artifact %r is not declared in artifacts[]" % declared
    if art["attempt_id"] != receipt["attempt_id"]:
        return "failed", "facts must come from this attempt's artifact; %r belongs to %r" % (
            declared, art["attempt_id"])
    target = resolve_artifact(artifact_root, declared)
    if target is None or not os.path.isfile(target):
        return "failed", "artifact bytes missing on disk"
    try:
        with open(target, "rb") as handle:
            facts = parser(handle.read())
    except (OSError, ValueError) as exc:
        return "failed", "invalid_observation: %s" % exc

    assertions = anchor["assertions"]
    mismatched = []
    for aid in definition["assertion_ids"]:
        assertion = assertions.get(aid)
        if assertion is None:
            return "failed", "frozen assertion %r is missing from the anchor" % aid
        for key, want in assertion.items():
            got = facts.get(key, "<absent>")
            if not _deep_equal(want, got):
                mismatched.append("%s:%s expected %r got %r" % (aid, key, want, got))

    if kind == "semantic":
        if mismatched:
            return "failed", "; ".join(mismatched)
        return "passed", "%d frozen assertions hold on parsed facts" % len(definition["assertion_ids"])

    must_fail = list(definition.get("must_fail") or [])
    if not must_fail:
        return "failed", "negative control freezes no must-fail assertion; it proves nothing"
    failed_ids = sorted({item.split(":", 1)[0] for item in mismatched})
    if not failed_ids:
        return "failed", "negative control matched a value it must reject (evaluator too weak)"
    if failed_ids != sorted(must_fail):
        return "failed", "negative control diverged on %r; frozen must-fail set is %r" % (
            failed_ids, sorted(must_fail))
    return "passed", "negative control rejects exactly %r on a format-valid observation" % (must_fail,)


def _evaluate_v2(schema, receipt, oracle, artifact_root, oracle_path=None):
    report = _blank_report()
    report["mode"] = "product"
    report["anchor"] = {}

    def fail(reason):
        report["reasons"].append(reason)
        report["verdict"] = "PROFILE_FAIL"
        return report

    # ---- 1 schema identity ------------------------------------------------
    major, why = schema_identity(schema)
    if why is not None:
        report["schema_errors"].append(why)
        return fail(why)
    report["schema_major_ok"] = major == PRODUCT_ACCEPTANCE_MAJOR
    if not report["schema_major_ok"]:
        return fail("schema identity %r is not the product major %r" % (major, PRODUCT_ACCEPTANCE_MAJOR))
    if receipt.get("schema_version") != PRODUCT_ACCEPTANCE_MAJOR:
        return fail(
            "unknown major schema_version %r against schema identity %r; MUST NOT be interpreted "
            "as success" % (receipt.get("schema_version"), major)
        )
    report["schema_errors"] = validate(receipt, schema)
    report["schema_ok"] = not report["schema_errors"]
    if not report["schema_ok"]:
        return fail("schema validation failed (%d errors): %s" % (
            len(report["schema_errors"]), "; ".join(report["schema_errors"][:4])))

    # ---- 2 anchor identity, self seal, and byte binding -------------------
    if not isinstance(oracle, dict):
        return fail("anchor document is %s, not an object" % type(oracle).__name__)
    if oracle.get("anchor_version") != ANCHOR_VERSION:
        return fail("anchor_version %r is not %r" % (oracle.get("anchor_version"), ANCHOR_VERSION))
    seal = anchor_seal(oracle)
    report["anchor"]["self_sha256"] = seal
    if oracle.get("self_sha256") != seal:
        return fail("anchor self seal mismatch: recomputed %s, document says %r" % (
            seal, oracle.get("self_sha256")))

    declared_block = receipt["oracle"]
    declared_path = resolve_artifact(artifact_root, declared_block["anchor_path"])
    if declared_path is None:
        return fail("anchor_path %r is outside the export root or malformed" % declared_block["anchor_path"])
    if not os.path.isfile(declared_path):
        return fail("anchor file %r is missing on disk" % declared_block["anchor_path"])
    actual_anchor_sha = sha256_file(declared_path)
    report["anchor"]["file_sha256"] = actual_anchor_sha
    if actual_anchor_sha != declared_block["anchor_sha256"]:
        return fail(
            "oracle_changed_old_digest: anchor bytes hash %s != receipt declared %s; the frozen "
            "definition was edited while the old digest was kept" % (actual_anchor_sha, declared_block["anchor_sha256"])
        )
    if oracle_path is not None and os.path.normcase(os.path.realpath(oracle_path)) != os.path.normcase(declared_path):
        return fail("anchor_path_mismatch: verifier read %r but the receipt declares %r" % (
            oracle_path, declared_path))
    try:
        on_disk = load_json(declared_path)
    except (OSError, json.JSONDecodeError) as exc:
        return fail("anchor file unreadable at the declared path: %s" % exc)
    if not _deep_equal(on_disk, oracle):
        return fail("anchor_content_mismatch: parsed anchor differs from the bytes at the declared path")

    profile = oracle["profile"]
    frozen_digest = profile_digest(profile)
    if receipt["profile_id"] != profile["id"]:
        return fail("profile_id %r != frozen anchor profile %r" % (receipt["profile_id"], profile["id"]))
    if receipt["profile_digest"] != frozen_digest:
        return fail("profile_digest %r != frozen profile digest %s" % (receipt["profile_digest"], frozen_digest))
    if declared_block["version"] != oracle["oracle_version"]:
        return fail("oracle version %r != anchor oracle_version %r" % (
            declared_block["version"], oracle["oracle_version"]))
    if sorted(declared_block["assertion_ids"]) != sorted(oracle["assertions"]):
        return fail("receipt assertion_ids %r != frozen assertion set %r" % (
            declared_block["assertion_ids"], sorted(oracle["assertions"])))
    if sorted(receipt["capability_ids"]) != sorted(profile["capabilities"]):
        return fail("capability_ids %r != frozen profile capabilities %r" % (
            receipt["capability_ids"], profile["capabilities"]))

    # ---- 3 ID uniqueness BEFORE any dict/set ------------------------------
    anchor_ids = list(oracle["required_check_ids"])
    if not anchor_ids:
        return fail("empty_required_set: the frozen anchor names no required check; 0/0 cannot pass")
    if len(anchor_ids) != len(set(anchor_ids)):
        return fail("duplicate_required_id in anchor: %r" % anchor_ids)
    receipt_ids = list(receipt["result"]["required_check_ids"])
    if len(receipt_ids) != len(set(receipt_ids)):
        return fail("duplicate_required_id in receipt: %r" % receipt_ids)
    if set(receipt_ids) != set(anchor_ids):
        return fail("receipt required_check_ids %r != frozen anchor %r" % (receipt_ids, anchor_ids))

    definitions = list(oracle["checks"])
    definition_ids = [item.get("id") for item in definitions]
    if len(definition_ids) != len(set(definition_ids)):
        return fail("duplicate_check_definition in anchor: %r" % definition_ids)
    if set(definition_ids) != set(anchor_ids):
        return fail("anchor check definitions %r != frozen required ids %r" % (definition_ids, anchor_ids))
    if not oracle["required_layers"]:
        return fail("empty_required_layers: the anchor claims no evidence layer")
    for layer in oracle["required_layers"]:
        if layer not in EVIDENCE_LAYERS:
            return fail("anchor required_layers names unknown layer %r" % layer)
        if not any(item["kind"] == layer for item in definitions):
            return fail(
                "empty_required_layer: anchor requires layer %r but freezes no check of that kind; "
                "a required layer cannot collapse to 0/0" % layer
            )

    check_ids = [check.get("id") for check in receipt["checks"]]
    if len(check_ids) != len(set(check_ids)):
        duplicates = sorted({cid for cid in check_ids if check_ids.count(cid) > 1})
        return fail(
            "duplicate_check_id: %r appears more than once; rejected before any dict/set, "
            "no first-wins, verdict is order-independent" % (duplicates,)
        )

    artifact_paths = [art["path"] for art in receipt["artifacts"]]
    if len(artifact_paths) != len(set(artifact_paths)):
        return fail("duplicate_artifact_path: %r" % artifact_paths)

    # ---- 4 execution contract, taken from the anchor ----------------------
    contract = oracle["execution_contract"]
    steps = list(contract["required_steps"])
    if not steps:
        return fail("empty_execution_contract: the frozen anchor has no required steps; 0/0 cannot pass")
    if len(steps) != len(set(steps)):
        return fail("duplicate_step in frozen execution contract: %r" % steps)
    expected_exit = contract["expected_exit"]
    if isinstance(expected_exit, bool) or not isinstance(expected_exit, int):
        return fail("invalid_anchor_exit_contract: expected_exit %r is not an integer" % (expected_exit,))
    execution = receipt["execution"]
    if list(execution["expected_steps"]) != steps:
        return fail("execution_plan_mismatch: receipt expected_steps %r != frozen %r" % (
            execution["expected_steps"], steps))
    if isinstance(execution["expected_exit"], bool) or execution["expected_exit"] != expected_exit:
        return fail("execution_plan_mismatch: receipt expected_exit %r != frozen %r" % (
            execution["expected_exit"], expected_exit))

    # ---- 5 execution / check / attempt terminal compatibility -------------
    terminal_problems = []
    if execution["terminal_state"] != contract["terminal_state"]:
        terminal_problems.append("terminal_state %r != frozen %r" % (
            execution["terminal_state"], contract["terminal_state"]))
    if execution["cancelled"] is not contract["cancelled"]:
        terminal_problems.append("cancelled=%r contradicts frozen %r" % (
            execution["cancelled"], contract["cancelled"]))
    if execution["cleanup"] not in contract["cleanup"]:
        terminal_problems.append("cleanup %r not in frozen %r" % (execution["cleanup"], contract["cleanup"]))
    if contract["backend_executed"] is True and execution["backend_executed"] is not True:
        terminal_problems.append("backend_executed=false; only an evaluator/utime ran")
    observed_exit = execution["observed_exit"]
    if isinstance(observed_exit, bool) or (observed_exit is not None and not isinstance(observed_exit, int)):
        terminal_problems.append("observed_exit %r is not an integer (True is not an exit code)" % (observed_exit,))
    completed = list(execution["completed_steps"])
    if len(completed) != len(set(completed)):
        terminal_problems.append("duplicate completed step: %r" % completed)
    missing_steps = [step for step in steps if step not in completed]
    if missing_steps:
        terminal_problems.append("required steps missing terminal result: %s" % ",".join(missing_steps))

    inventory = oracle["attempts"]
    inventory_ids = [item["attempt_id"] for item in inventory]
    if len(inventory_ids) != len(set(inventory_ids)):
        return fail("duplicate_attempt_id in frozen inventory: %r" % inventory_ids)
    inventory_by_id = {item["attempt_id"]: item for item in inventory}
    attempt_id = receipt["attempt_id"]
    if attempt_id not in inventory_by_id:
        return fail("unknown_attempt: attempt_id %r is not in the frozen run inventory" % attempt_id)
    if inventory_by_id[attempt_id]["parent_attempt_id"] != receipt["parent_attempt_id"]:
        return fail(
            "parent_pointer_mismatch: frozen inventory records parent %r, receipt says %r"
            % (inventory_by_id[attempt_id]["parent_attempt_id"], receipt["parent_attempt_id"])
        )
    if receipt["parent_attempt_id"] == attempt_id:
        return fail("retry_reuses_parent_attempt_id: a retry MUST be a new attempt")
    if oracle["selected_terminal_attempt"] != attempt_id:
        return fail("non_terminal_attempt: receipt is %r but the frozen terminal attempt is %r" % (
            attempt_id, oracle["selected_terminal_attempt"]))

    # ---- 6 artifact ownership, bytes, producer attempt --------------------
    art_by_path = {}
    current_prefix = ("attempts", attempt_id)
    for art in receipt["artifacts"]:
        target = resolve_artifact(artifact_root, art["path"])
        if target is None:
            return fail("artifact_path_escape: %r is outside the export root or malformed" % art["path"])
        parts = PurePosixPath(art["path"].replace("\\", "/")).parts
        if art["attempt_id"] == attempt_id:
            if art.get("reused") is True:
                return fail("artifact_ownership: current-attempt artifact %r is marked reused" % art["path"])
            if parts[:2] != current_prefix:
                return fail(
                    "artifact_ownership: %r is not under attempts/%s/ (component ownership)"
                    % (art["path"], attempt_id)
                )
        else:
            if art.get("reused") is not True:
                return fail("reused_artifact_not_declared: %r belongs to attempt %r and is not marked reused" % (
                    art["path"], art["attempt_id"]))
            owner = inventory_by_id.get(art["attempt_id"])
            if owner is None:
                return fail(
                    "unknown_producer_attempt: %r claims attempt %r which the frozen inventory "
                    "does not contain" % (art["path"], art["attempt_id"])
                )
            frozen_art = next((item for item in owner["artifacts"] if item["path"] == art["path"]), None)
            if frozen_art is None:
                return fail("unknown_producer_artifact: %r is not recorded for attempt %r" % (
                    art["path"], art["attempt_id"]))
            if frozen_art["sha256"] != art["sha256"] or frozen_art["size_bytes"] != art["size_bytes"]:
                return fail("reused_artifact_drift: %r declared identity differs from the frozen inventory" % (
                    art["path"],))
        ok, _disk, detail = _artifact_disk_state(artifact_root, art)
        if not ok:
            if art["attempt_id"] != attempt_id:
                return fail("parent_bytes_changed: %s (%s)" % (art["path"], detail))
            return fail("artifact_integrity: %s (%s)" % (art["path"], detail))
        art_by_path[art["path"]] = art

    # ---- 7/8 per-check recompute and aggregation over the frozen set ------
    by_check = {check["id"]: check for check in receipt["checks"]}
    by_definition = {item["id"]: item for item in definitions}
    for cid in anchor_ids:
        definition = by_definition[cid]
        check = by_check.get(cid)
        if check is None:
            report["missing_required"].append(cid)
            report["check_results"].append({
                "id": cid, "kind": definition["kind"], "status": "not_run",
                "detail": "required check absent from receipt",
            })
            continue
        status, detail = _v2_check(definition, check, receipt, oracle, artifact_root, art_by_path, terminal_problems)
        native = (check.get("source_status") or "").strip().upper()
        if status == "passed" and native in _NATIVE_NONPASS:
            status = "blocked"
            detail = (
                "native source_status %r cannot be promoted to passed by residual facts (%s)"
                % (check.get("source_status"), detail)
            )
        declared = check.get("status")
        if status == "passed" and declared != "passed":
            status = declared if declared in NONPASS else "unknown"
            detail = "declared status %r lowers a recomputable pass (%s)" % (declared, detail)
        report["check_results"].append({
            "id": cid, "kind": definition["kind"], "status": status, "detail": detail,
        })

    report["checks_total"] = len(anchor_ids)
    report["checked"] = sum(1 for row in report["check_results"] if row["id"] not in report["missing_required"])
    report["passed"] = sum(1 for row in report["check_results"] if row["status"] == "passed")
    report["failed"] = sum(1 for row in report["check_results"] if row["status"] in ("failed", "error"))
    report["skipped"] = sum(1 for row in report["check_results"] if row["status"] in INCOMPLETE)
    for row in report["check_results"]:
        layer = report["layer"].setdefault(row["kind"] or "unknown", [0, 0])
        layer[1] += 1
        if row["status"] == "passed":
            layer[0] += 1

    if report["missing_required"]:
        report["reasons"].append("required checks absent from the receipt: %s" % ",".join(report["missing_required"]))
    for row in report["check_results"]:
        if row["status"] != "passed":
            report["reasons"].append("%s(%s)=%s: %s" % (row["id"], row["kind"], row["status"], row["detail"]))
    declared_verdict = receipt["result"]["verdict"]
    if declared_verdict != "pass":
        report["reasons"].append(
            "declared result.verdict=%r can only lower the recomputed verdict" % declared_verdict)
    if terminal_problems:
        report["reasons"].append(
            "execution_record_incomplete: residual facts cannot restore profile eligibility ("
            + "; ".join(terminal_problems) + ")")

    nothing_ran = all(row["status"] == "not_run" for row in report["check_results"]) if report["check_results"] else True
    if report["failed"] > 0 or terminal_problems or declared_verdict in ("fail", "outcome_unknown"):
        report["verdict"] = "PROFILE_FAIL"
    elif report["skipped"] > 0 or report["missing_required"]:
        report["verdict"] = "PROFILE_NOT_RUN" if nothing_ran else "PROFILE_BLOCKED"
    elif report["passed"] == report["checks_total"] and report["checks_total"] > 0 and declared_verdict == "pass":
        report["verdict"] = "PROFILE_PASS"
    else:
        report["verdict"] = "PROFILE_BLOCKED"
    if report["verdict"] == "PROFILE_PASS":
        report["reasons"].append(
            "all %d frozen required checks passed under the external anchor" % report["checks_total"])
    return report


def evaluate(schema, receipt, oracle, artifact_root, product=False, oracle_path=None):
    """Dispatch on the schema's own identity; never on a global guess.

    A schema whose form or `$id` is not recognised fails closed in BOTH modes, so a
    boolean `false` schema can no longer behave like an empty (accept-everything) schema.
    """
    major, why = schema_identity(schema)
    if why is not None:
        report = _blank_report()
        report["schema_errors"].append(why)
        report["reasons"].append(why)
        report["mode"] = "product" if product else "legacy"
        return report
    if product:
        report = _blank_report()
        report["mode"] = "product"
        report["verdict"] = "PROFILE_BLOCKED"
        report["reasons"].append(
            "static receipt evaluation cannot attest a product run; use run-receipt.3 with "
            "--plan, caller-supplied --expected-plan-sha256 and --runner-terminal"
        )
        return report
    if major == PRODUCT_ACCEPTANCE_MAJOR:
        report = _evaluate_v2(schema, receipt, oracle, artifact_root, oracle_path=oracle_path)
        report["mode"] = "static-v2-diagnostic"
        return report
    if major == "run-receipt.3":
        report = _blank_report()
        report["verdict"] = "PROFILE_BLOCKED"
        report["reasons"].append("run-receipt.3 requires the trusted plan and actual runner terminal")
        return report
    return _evaluate_v1(schema, receipt, oracle, artifact_root)


# ------------------------------------------------------------------- aggregate

def _evaluate_v1(schema, receipt, oracle, artifact_root):
    """Full evaluation. Pure with respect to inputs; returns a report dict."""
    report = {
        "schema_ok": False,
        "schema_errors": [],
        "schema_major_ok": False,
        "checks_total": 0,
        "checked": 0,
        "passed": 0,
        "failed": 0,
        "stale": 0,
        "skipped": 0,
        "missing_required": [],
        "layer": {"integrity": [0, 0], "execution": [0, 0], "semantic": [0, 0], "negative": [0, 0]},
        "check_results": [],
        "stale_detail": [],
        "retry_problems": [],
        "freeze_problems": [],
        "reasons": [],
        "verdict": "PROFILE_FAIL",
    }

    report["schema_errors"] = validate(receipt, schema)
    report["schema_ok"] = not report["schema_errors"]
    if not report["schema_ok"]:
        report["reasons"].append("schema validation failed (%d errors)" % len(report["schema_errors"]))
        return report

    version = receipt.get("schema_version", "")
    report["schema_major_ok"] = version == SCHEMA_MAJOR_SUPPORTED
    if not report["schema_major_ok"]:
        report["reasons"].append(
            "unknown major schema_version %r; MUST NOT be interpreted as success" % version
        )
        return report

    # Required set frozen before the run: oracle is the authority, receipt must agree.
    frozen_required = list(oracle.get("required_check_ids") or [])
    declared_required = list((receipt.get("result") or {}).get("required_check_ids") or [])
    if not frozen_required:
        report["freeze_problems"].append("oracle freezes an empty required set; empty set cannot pass")
    if set(frozen_required) != set(declared_required):
        report["freeze_problems"].append(
            "receipt required_check_ids %r != oracle frozen %r" % (declared_required, frozen_required)
        )

    by_id = {}
    for check in receipt.get("checks", []):
        by_id.setdefault(check.get("id"), check)

    for cid in frozen_required:
        check = by_id.get(cid)
        if check is None:
            report["missing_required"].append(cid)
            report["check_results"].append(
                {"id": cid, "kind": None, "status": "not_run", "detail": "required check absent from receipt"}
            )
            continue
        status, detail = recompute_check(check, receipt, artifact_root, oracle)
        if status is None:
            declared = check.get("status")
            if declared in PASSING and not SKIP_COUNTS_AS_PASS:
                status, detail = "unknown", "%s; declared passed but not independently recomputable" % detail
            elif declared in PASSING and SKIP_COUNTS_AS_PASS:
                status = "passed"
            elif declared in NONPASS:
                status = "passed" if (SKIP_COUNTS_AS_PASS and declared == "skipped") else declared
            else:
                status = "unknown"
        report["check_results"].append(
            {"id": cid, "kind": check.get("kind"), "status": status, "detail": detail}
        )

    # Optional checks are reported, never aggregated into the required verdict.
    for cid, check in by_id.items():
        if cid in frozen_required:
            continue
        status, detail = recompute_check(check, receipt, artifact_root)
        if status is None:
            status = check.get("status") or "unknown"
        report["check_results"].append(
            {"id": cid, "kind": check.get("kind"), "status": status, "detail": detail, "optional": True}
        )

    report["stale_detail"] = stale_artifacts(receipt, oracle) if STALE_GUARD_ENABLED else []
    report["stale"] = len(report["stale_detail"])
    report["retry_problems"] = retry_problems(receipt, oracle, artifact_root)

    # Counters over the frozen required set only.
    required_results = [r for r in report["check_results"] if not r.get("optional")]
    report["checks_total"] = len(frozen_required)
    report["checked"] = sum(1 for r in required_results if r["id"] not in report["missing_required"])
    report["passed"] = sum(1 for r in required_results if r["status"] == "passed")
    report["failed"] = sum(1 for r in required_results if r["status"] in ("failed", "error"))
    report["skipped"] = sum(1 for r in required_results if r["status"] in INCOMPLETE)
    for r in required_results:
        layer = report["layer"].setdefault(r.get("kind") or "unknown", [0, 0])
        layer[1] += 1
        if r["status"] == "passed":
            layer[0] += 1

    hard_fail = (
        report["failed"] > 0
        or report["stale"] > 0
        or bool(report["retry_problems"])
        or bool(report["freeze_problems"])
    )
    incomplete = report["skipped"] > 0 or bool(report["missing_required"])
    nothing_ran = all(r["status"] == "not_run" for r in required_results) if required_results else True

    if hard_fail:
        report["verdict"] = "PROFILE_FAIL"
    elif incomplete:
        report["verdict"] = "PROFILE_NOT_RUN" if nothing_ran else "PROFILE_BLOCKED"
    elif report["passed"] == report["checks_total"] and report["checks_total"] > 0:
        report["verdict"] = "PROFILE_PASS"
    else:
        report["verdict"] = "PROFILE_BLOCKED"

    for r in required_results:
        if r["status"] != "passed":
            report["reasons"].append("%s(%s)=%s: %s" % (r["id"], r.get("kind"), r["status"], r.get("detail")))
    for s in report["stale_detail"]:
        report["reasons"].append("stale_not_fresh: %s (%s)" % (s["artifact"], s["reason"]))
    report["reasons"].extend(report["retry_problems"])
    report["reasons"].extend(report["freeze_problems"])
    if not report["reasons"]:
        report["reasons"].append("all %d frozen required checks independently recomputed as passed" % report["checks_total"])
    return report


def format_report(report):
    if "profile_scope" in report:
        rows = report["check_results"]
        return "\n".join([
            "PRODUCT_GATE=YES", "PROFILE_SCOPE=" + report["profile_scope"],
            "checks_total=%d checked=%d passed=%d" % (report["checks_total"], len(rows), sum(row["status"] == "passed" for row in rows)),
            *["  check %s kind=%s status=%s :: %s" % (row["id"], row["kind"], row["status"], row["detail"]) for row in rows],
            *["reason: " + reason for reason in report["reasons"]],
            "VERDICT=" + report["verdict"],
        ])
    if report.get("mode") == "product":
        lines = [
            "PRODUCT_GATE=YES",
            "ANCHOR_SELF_SEAL=%s" % report.get("anchor", {}).get("self_sha256", "<none>"),
            "ANCHOR_FILE_SHA256=%s" % report.get("anchor", {}).get("file_sha256", "<none>"),
        ]
    else:
        lines = ["STATIC_V2_DIAGNOSTIC_ONLY=YES" if report.get("mode") == "static-v2-diagnostic" else "LEGACY_DIAGNOSTIC_ONLY=YES"]
    lines += [
        "SCHEMA_STRICT=%s" % ("YES" if report["schema_ok"] else "NO"),
        "SCHEMA_MAJOR_SUPPORTED=%s" % ("YES" if report["schema_major_ok"] else "NO"),
        "LAYERS integrity=%d/%d execution=%d/%d semantic=%d/%d negative=%d/%d"
        % (
            report["layer"]["integrity"][0], report["layer"]["integrity"][1],
            report["layer"]["execution"][0], report["layer"]["execution"][1],
            report["layer"]["semantic"][0], report["layer"]["semantic"][1],
            report["layer"]["negative"][0], report["layer"]["negative"][1],
        ),
        "checks_total=%d checked=%d passed=%d failed=%d stale=%d skipped=%d"
        % (
            report["checks_total"], report["checked"], report["passed"],
            report["failed"], report["stale"], report["skipped"],
        ),
    ]
    for r in report["check_results"]:
        lines.append(
            "  check %s kind=%s status=%s%s :: %s"
            % (r["id"], r.get("kind"), r["status"], " optional" if r.get("optional") else "", r.get("detail"))
        )
    for reason in report["reasons"]:
        lines.append("reason: %s" % reason)
    lines.append("VERDICT=%s" % report["verdict"])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--schema")
    parser.add_argument("--receipt")
    parser.add_argument("--oracle")
    parser.add_argument("--plan")
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--runner-terminal")
    parser.add_argument("--artifact-root", default=None)
    parser.add_argument("--product", action="store_true",
                        help="product gate: require a caller-pinned plan and observed v3 runner terminal")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    if args.product:
        if not args.plan or not args.expected_plan_sha256 or not args.runner_terminal:
            report = _blank_report()
            report.update(mode="product", verdict="PROFILE_BLOCKED")
            report["reasons"].append("product provenance requires --plan, caller-supplied --expected-plan-sha256 and --runner-terminal; legacy/demo receipts are static diagnostics only")
        elif args.schema or args.oracle or args.artifact_root:
            report = _blank_report()
            report.update(mode="product", verdict="PROFILE_BLOCKED")
            report["reasons"].append("strict plan mode owns the schema, oracle and artifact root; pass only --plan, --expected-plan-sha256, --runner-terminal and optional --receipt")
        else:
            import runner_evidence
            report = runner_evidence.verify_run(args.plan, args.expected_plan_sha256, args.runner_terminal, args.receipt)
        print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) if args.as_json else format_report(report))
        return VERDICT_EXIT[report["verdict"]]
    if args.plan or args.expected_plan_sha256 or args.runner_terminal or not args.schema or not args.receipt or not args.oracle:
        print("VERDICT=PROFILE_BLOCKED\nreason: diagnostic mode needs --schema --receipt --oracle; strict plan mode needs --product")
        return 4
    try:
        schema = load_json(args.schema)
        receipt = load_json(args.receipt)
        oracle = load_json(args.oracle)
    except (OSError, json.JSONDecodeError) as exc:
        print("VERDICT=PROFILE_FAIL")
        print("reason: unreadable input: %s" % exc)
        return 4

    artifact_root = args.artifact_root or os.path.dirname(os.path.abspath(args.receipt))
    report = evaluate(schema, receipt, oracle, artifact_root,
                      product=args.product, oracle_path=args.oracle)
    if args.as_json:
        print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        print(format_report(report))
    return VERDICT_EXIT[report["verdict"]]


if __name__ == "__main__":
    sys.exit(main())

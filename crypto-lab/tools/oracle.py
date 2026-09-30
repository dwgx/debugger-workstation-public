#!/usr/bin/env python
"""oracle.py -- cross-check the analyzer with PyJWT, from the Python side.

Same role as `oracle-node.mjs`, a genuinely different implementation lineage: PyJWT is
not jsonwebtoken, was written by different people, and makes different choices about what
to enforce by default (it *does* reject a missing `exp` when you pass `require`, and it
raises a distinct exception class for each failure).

The point of running both is independence. Three implementations agreeing on a verdict is
evidence; one implementation agreeing with itself is not.

Output is JSON data on stdout, exit 0 unless the invocation was wrong.

usage: oracle.py --token <jws> [--key none|secret|rsa-public]
                 [--secret s] [--rsa-pub path] [--algorithms HS256,RS256]
                 [--require exp,aud] [--issuer X] [--audience Y]
"""
import argparse
import json
import sys


def main() -> int:
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--token")
    ap.add_argument("--key", default="none")
    ap.add_argument("--secret", default="secret")
    ap.add_argument("--rsa-pub")
    ap.add_argument("--algorithms", default="")
    ap.add_argument("--require", default="")
    ap.add_argument("--issuer")
    ap.add_argument("--audience")
    args, _unknown = ap.parse_known_args()

    if not args.token:
        print(json.dumps({"ok": False, "error": "usage: --token <jws>"}))
        return 2

    algorithms = [a.strip() for a in args.algorithms.split(",") if a.strip()]
    require = [c.strip() for c in args.require.split(",") if c.strip()]

    out = {
        "oracle": "PyJWT",
        "version": None,
        "key_mode": args.key,
        "algorithms": algorithms,
        "require": require,
    }

    try:
        import jwt
        from jwt import exceptions as jex

        out["version"] = jwt.__version__

        # decode_complete is unconditional inspection -- no verification, no policy.
        try:
            complete = jwt.api_jwt.decode_complete(args.token, options={"verify_signature": False})
            out["decoded"] = complete
            out["decoded_alg"] = (complete.get("header") or {}).get("alg")
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            out["decoded_error"] = type(exc).__name__

        key = None
        if args.key == "secret":
            key = args.secret
        elif args.key == "rsa-public":
            if not args.rsa_pub:
                raise ValueError("--key rsa-public needs --rsa-pub")
            if "-----BEGIN" in args.rsa_pub:
                key = args.rsa_pub
            else:
                with open(args.rsa_pub, "r", encoding="utf-8") as fh:
                    key = fh.read()
        elif args.key != "none":
            raise ValueError(f"unknown --key {args.key}")

        options = {}
        if require:
            options["require"] = require
        kwargs = {"options": options} if options else {}
        if args.issuer:
            kwargs["issuer"] = args.issuer
        if args.audience:
            kwargs["audience"] = args.audience

        try:
            if not algorithms:
                # No allowlist given: PyJWT insists on one, which is itself the lesson.
                payload = jwt.decode(
                    args.token,
                    key,
                    options={**options, "verify_signature": False},
                    **{k: v for k, v in kwargs.items() if k != "options"},
                )
                out["verified"] = False
                out["claims"] = payload
                out["error"] = {
                    "name": "NoAlgorithmsSupplied",
                    "message": "no --algorithms allowlist given; signature NOT verified (PyJWT requires the caller to name the accepted algorithms)",
                }
            else:
                payload = jwt.decode(args.token, key, algorithms=algorithms, **kwargs)
                out["verified"] = True
                out["claims"] = payload
        except jex.ExpiredSignatureError as exc:
            out["verified"] = False
            out["error"] = {"name": "ExpiredSignatureError", "message": str(exc)}
        except jex.MissingRequiredClaimError as exc:
            out["verified"] = False
            out["error"] = {"name": "MissingRequiredClaimError", "message": str(exc)}
        except jex.InvalidAlgorithmError as exc:
            out["verified"] = False
            out["error"] = {"name": "InvalidAlgorithmError", "message": str(exc)}
        except jex.InvalidAudienceError as exc:
            out["verified"] = False
            out["error"] = {"name": "InvalidAudienceError", "message": str(exc)}
        except jex.InvalidIssuerError as exc:
            out["verified"] = False
            out["error"] = {"name": "InvalidIssuerError", "message": str(exc)}
        except jex.InvalidSignatureError as exc:
            out["verified"] = False
            out["error"] = {"name": "InvalidSignatureError", "message": str(exc)}
        except jex.InvalidTokenError as exc:
            out["verified"] = False
            out["error"] = {"name": type(exc).__name__, "message": str(exc)}
    except Exception as exc:  # noqa: BLE001
        out["error"] = {"name": type(exc).__name__, "message": str(exc)}

    print(json.dumps(out, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())

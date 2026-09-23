#!/usr/bin/env python3
"""Build/run the first-party Go adapter, or verify an offline execution packet.

Verification checks integrity and record consistency, not engine honesty,
producer authentication, independent authorship, or a second grading oracle.
Requires jsonschema; engine execution is Linux-only and is not sandboxed.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
from functools import lru_cache

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent.parent
MIB = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def constant(value):
        raise ValueError(f"nonfinite JSON number: {value}")

    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


@lru_cache(maxsize=None)
def validator(name):
    schema = strict_json((ROOT / "schemas" / f"hushspec-{name}.schema.json").read_bytes())
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate(name, value):
    error = next(validator(name).iter_errors(value), None)
    require(error is None, f"{name}: {error}")


def open_artifact(root, name):
    """Open every component without following symlinks, then require a file."""
    parts = PurePosixPath(name).parts
    require(parts and not name.startswith("/") and "\\" not in name
            and all(part not in (".", "..") for part in parts), "unsafe artifact path")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            os.close(file_fd)
            raise ValueError(f"not a regular artifact: {name}")
        return os.fdopen(file_fd, "rb")
    except OSError as error:
        raise ValueError(f"cannot safely open artifact {name}: {error}") from error
    finally:
        os.close(fd)


def read_bytes(root, artifact):
    with open_artifact(root, artifact["path"]) as source:
        data = source.read(min(artifact["bytes"], 64 * MIB) + 1)
    require(len(data) == artifact["bytes"] and hashlib.sha256(data).hexdigest() == artifact["sha256"],
            f"JSON artifact changed or exceeds limit: {artifact['path']}")
    return data


def read_json(root, artifact):
    return strict_json(read_bytes(root, artifact))


def input_wire_bytes(request):
    """Extract the exact top-level input slice after strict request validation."""
    text = request.decode("utf-8")
    decoder = json.JSONDecoder()
    index = text.index("{") + 1
    while True:
        while text[index] in " \t\r\n,":
            index += 1
        key, index = decoder.raw_decode(text, index)
        while text[index] in " \t\r\n":
            index += 1
        require(text[index] == ":", "invalid request separator")
        index += 1
        while text[index] in " \t\r\n":
            index += 1
        start = index
        _, index = decoder.raw_decode(text, index)
        if key == "input":
            return text[start:index].encode("utf-8")


def verify_packet(root: Path, require_level: int | None = None):
    """Return the report only after every artifact and cross-record check passes."""
    root = Path(root)
    with open_artifact(root, "execution.json") as source:
        data = source.read(64 * MIB + 1)
    require(len(data) <= 64 * MIB, "execution record too large")
    record = strict_json(data)
    validate("conformance-execution-experimental.v1", record)
    artifacts = [record[key] for key in ("engine", "controller", "profile", "manifest", "report")]
    artifacts += record["corpus"] + record["builtins"] + record["declared_materials"]
    artifacts += [case[key] for case in record["cases"] for key in ("request", "input", "stdout", "stderr")]
    require(len({a["path"] for a in artifacts}) == len(artifacts), "duplicate artifact paths")
    require(sum(a["bytes"] for a in artifacts) <= 1024 * MIB, "packet exceeds verification budget")
    for artifact in artifacts:
        with open_artifact(root, artifact["path"]) as source:
            require(os.fstat(source.fileno()).st_size == artifact["bytes"], f"artifact size mismatch: {artifact['path']}")
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        require(digest == artifact["sha256"], f"artifact digest mismatch: {artifact['path']}")

    report = read_json(root, record["report"])
    validate("conformance-report.v1", report)
    profile = read_json(root, record["profile"])
    validate("engine-profile-experimental.v1", profile)
    manifest = read_json(root, record["manifest"])
    require(report["implementation"] == record["implementation"] == profile["implementation"], "implementation identity mismatch")
    require(profile["args"] == record["args"], "argument identity mismatch")
    require(profile["executable"]["sha256"] == record["engine"]["sha256"], "engine identity mismatch")
    require([a["sha256"] for a in profile.get("materials", [])] == [a["sha256"] for a in record["declared_materials"]], "material identity mismatch")
    require(report["manifest_sha256"] == record["manifest"]["sha256"], "manifest identity mismatch")
    require(report["fixtures_version"] == manifest["fixtures_version"], "fixture version mismatch")
    require(report["generated_at"] == record["generated_at"], "timestamp mismatch")
    expected_corpus = {"inputs/" + entry["path"]: entry["sha256"] for entry in manifest["files"]}
    require(len(expected_corpus) == len(manifest["files"]), "duplicate manifest paths")
    require(expected_corpus == {a["path"]: a["sha256"] for a in record["corpus"]}, "corpus inventory mismatch")

    planned = record["planned"]
    cases = record["cases"]
    require(len({p["case_id"] for p in planned}) == len(planned), "duplicate planned case")
    require([c["case_id"] for c in cases] == [p["case_id"] for p in planned[:len(cases)]], "terminal record cardinality or order mismatch")
    require(len(cases) <= len(planned), "foreign terminal records")
    if record["abort_reason"] is None:
        require(len(cases) == len(planned), "missing terminal record without abort")
    key = lambda slot: (slot["path"], slot["category"], slot["level"])
    slots = [s for p in planned for s in p["slots"]] + record["unattempted"]
    require(len(set(map(key, slots))) == len(slots), "duplicate planned result slot")
    results = {key(r): r for r in report["results"]}
    require(len(results) == len(report["results"]), "duplicate report result slot")
    require(set(results) == set(map(key, slots)), "missing or foreign result slots")
    for slot in record["unattempted"] + [s for p in planned[len(cases):] for s in p["slots"]]:
        require(results[key(slot)]["status"] == "not_attempted", "undispatched result reported as attempted")

    for index, case in enumerate(cases):
        plan = planned[index]
        request = read_json(root, case["request"])
        validate("engine-request-experimental.v1", request)
        binding = {"protocol": record["protocol"], "run_id": record["run_id"], "case_id": plan["case_id"],
                   "operation": plan["operation"], "input_sha256": plan["input_sha256"]}
        require(all(request[k] == v for k, v in binding.items()), "request binding mismatch")
        require(case["input"]["sha256"] == binding["input_sha256"], "input binding mismatch")
        require(request["input"] == read_json(root, case["input"]), "request/input mismatch")
        wire_input = input_wire_bytes(read_bytes(root, case["request"]))
        require(hashlib.sha256(wire_input).hexdigest() == binding["input_sha256"], "request input wire digest mismatch")
        process = case["process"]
        failed = process["failure"] is not None or case["protocol_failure"] is not None
        require(case["stdout"]["bytes"] <= record["limits"]["stdout_bytes"] and case["stderr"]["bytes"] <= record["limits"]["stderr_bytes"], "per-case output budget exceeded")
        if failed:
            require(index == len(cases) - 1 and record["abort_reason"] is not None, "failure did not abort dispatch")
            require(all(results[key(s)]["status"] == "fail" for s in plan["slots"]), "process/protocol failure counted as a refusal")
            continue
        require(process["exit_code"] == 0 and process["signal"] is None and not process["truncated"], "unsuccessful process lacks failure")
        response = read_json(root, case["stdout"])
        validate("engine-response-experimental.v1", response)
        require(all(response[k] == v for k, v in binding.items()), "response binding mismatch")
        require(response["result"]["status"] != "error", "engine error lacks protocol failure")
        if response["result"]["status"] == "unsupported":
            require(all(results[key(s)]["status"] == "not_attempted" for s in plan["slots"]), "unsupported observation counted as attempted")
    require(sum(c[k]["bytes"] for c in cases for k in ("stdout", "stderr")) <= record["limits"]["total_output_bytes"], "aggregate output budget exceeded")
    require(sum(c[k]["bytes"] for c in cases for k in ("request", "input")) <= record["limits"]["total_request_bytes"], "aggregate request budget exceeded")

    highest = None
    for level in range(6):
        counts = Counter(r["status"] for r in report["results"] if r["level"] == level)
        status = "fail" if counts["fail"] else "not_attempted" if counts["not_attempted"] or not counts["pass"] else "pass"
        summary = report["levels"][str(level)]
        require(summary["status"] == status and (summary["passed"], summary["failed"], summary["skipped"]) ==
                (counts["pass"], counts["fail"], counts["not_attempted"]), "report level aggregation mismatch")
        if status == "pass" and (level == 0 or highest == level - 1):
            highest = level
    require(report.get("highest_level") == highest, "highest level mismatch")
    qualified = record["abort_reason"] is None and highest is not None and highest >= record["requested_level"]
    require(record["outcome"] == ("qualified" if qualified else "not_qualified"), "outcome mismatch")
    if require_level is not None:
        require(qualified and record["requested_level"] == require_level and highest >= require_level, f"requested L{require_level} not qualified")
    return report


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", type=Path, help="new retained build/run directory")
    group.add_argument("--verify", type=Path, help="existing packet directory; does not execute its images")
    args = parser.parse_args()
    if args.verify:
        report = verify_packet(args.verify)
        print(f"packet integrity verified; highest level: {report['highest_level']}; not authenticated provenance")
        return 0
    require(sys.platform == "linux", "external acceptance requires Linux")
    out = args.out.absolute()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    binary = out / "hushspec-conformance-go"
    subprocess.run(["go", "build", "-trimpath", "-o", str(binary), "./cmd/hushspec-conformance"],
                   cwd=ROOT / "packages/go", env={**os.environ, "CGO_ENABLED": "0"}, check=True)
    source_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT))
    profile = {"protocol": "0.1.0", "implementation": {"name": "hushspec Go SDK (first-party bring-up)",
               "version": source_sha + ("-dirty" if dirty else ""), "language": "Go"},
               "executable": {"path": str(binary), "sha256": digest(binary)}, "args": [], "error_codes": "registry",
               "materials": [{"path": str(ROOT / "packages/go" / name), "sha256": digest(ROOT / "packages/go" / name)} for name in ("go.mod", "go.sum")]}
    profile_path = out / "engine-profile.json"
    profile_path.write_text(json.dumps(profile, indent=2) + "\n")
    # Release mode bounds retention and hashing cost without changing limits.
    subprocess.run(["cargo", "build", "--release", "--locked", "-p", "hushspec-testkit", "--bin", "hushspec-testkit"], cwd=ROOT, check=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target.is_absolute():
        target = ROOT / target
    command = [str(target / "release/hushspec-testkit"), "external", "--engine", str(profile_path),
               "--fixtures", str(ROOT / "fixtures"), "--out", str(out / "packet"), "--level", "3", "--source-sha", source_sha]
    for variable, option in [("GITHUB_RUN_ID", "--ci-run"), ("GITHUB_RUN_ATTEMPT", "--ci-attempt")]:
        if os.environ.get(variable):
            command.extend([option, os.environ[variable]])
    result = subprocess.run(command, cwd=ROOT, check=False)
    require(result.returncode in (0, 1), f"controller infrastructure failure: exit {result.returncode}; artifacts retained at {out}")
    report = verify_packet(out / "packet")
    require(result.returncode == 0, f"Go did not qualify; packet retained at {out}")
    verify_packet(out / "packet", require_level=3)
    print(f"first-party Go L3 qualified; {len(report['results'])} result slots verified; packet: {out / 'packet'}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError, RecursionError, subprocess.CalledProcessError) as error:
        print(f"external conformance: {error}", file=sys.stderr)
        raise SystemExit(1)

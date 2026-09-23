"""Packet integrity checks use a tiny synthetic packet, never an engine oracle."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from run_external_conformance import strict_json, verify_packet


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        identity = {"name": "test", "version": "test", "language": "test"}
        slot = {"path": "fixtures/one.yaml/parse", "category": "parse", "level": 0}
        policy = b"hushspec: '1.0.0'"
        corpus = self.put("inputs/fixtures/one.yaml", policy)
        manifest = {"manifest_version": "0.1", "fixtures_version": "1.0.0", "generated_at": "2026-09-23T00:00:00Z", "files": [
            {"path": "fixtures/one.yaml", "sha256": corpus["sha256"], "category": "valid", "module": "core", "level": 1}]}
        engine = self.put("images/engine", b"synthetic engine identity")
        profile = {"protocol": "0.1.0", "implementation": identity, "executable": {"path": "engine", "sha256": engine["sha256"]}, "args": [], "error_codes": "none"}
        raw_input = encoded({"policy": policy.decode()})
        binding = {"protocol": "0.1.0", "run_id": "test-run", "case_id": "one", "operation": "parse", "input_sha256": hashlib.sha256(raw_input).hexdigest()}
        case = {"case_id": "one", "input": self.put("cases/0/input.json", raw_input),
                "request": self.put("cases/0/request.json", encoded({**binding, "input": json.loads(raw_input)})),
                "stdout": self.put("cases/0/stdout", encoded({**binding, "result": {"status": "ok", "value": {"hushspec": "1.0.0"}}})),
                "stderr": self.put("cases/0/stderr", b""), "protocol_failure": None,
                "process": {"exit_code": 0, "signal": None, "failure": None, "elapsed_ms": 1, "truncated": False}}
        levels = {str(i): {"status": "not_attempted", "passed": 0, "failed": 0, "skipped": 0} for i in range(6)}
        levels["0"] = {"status": "pass", "passed": 1, "failed": 0, "skipped": 0}
        manifest_artifact = self.put("inputs/manifest.json", encoded(manifest))
        self.report = {"implementation": identity, "fixtures_version": "1.0.0", "manifest_sha256": manifest_artifact["sha256"],
                       "levels": levels, "highest_level": 0, "results": [{**slot, "status": "pass"}], "generated_at": "2026-09-23T00:00:00Z"}
        self.record = {"protocol": "0.1.0", "run_id": "test-run", "implementation": identity, "requested_level": 0,
                       "outcome": "qualified", "abort_reason": None, "generated_at": self.report["generated_at"], "declared_build_context": {},
                       "controller": self.put("images/controller", b"synthetic controller identity"), "engine": engine,
                       "profile": self.put("inputs/profile.json", encoded(profile)), "manifest": manifest_artifact,
                       "corpus": [corpus], "builtins": [], "declared_materials": [], "args": [],
                       "environment": {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}, "os": "linux", "architecture": "test",
                       "limits": {"timeout_ms": 2000, "total_timeout_ms": 300000, "stdout_bytes": 1048576, "stderr_bytes": 262144,
                                  "total_output_bytes": 67108864, "total_request_bytes": 67108864},
                       "planned": [{"case_id": "one", "operation": "parse", "input_sha256": binding["input_sha256"], "slots": [slot]}],
                       "unattempted": [], "cases": [case], "report": self.put("report.json", encoded(self.report)),
                       "limitations": ["Synthetic unsigned test packet, not qualification evidence."]}
        self.save()

    def put(self, path, data):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
        return {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def save(self):
        (self.root / "execution.json").write_bytes(encoded(self.record))

    def test_valid_packet_and_required_level(self):
        self.assertEqual(verify_packet(self.root)["highest_level"], 0)
        with self.assertRaises(ValueError):
            verify_packet(self.root, require_level=3)

    def test_tampered_report_or_output_bytes(self):
        for path in ["report.json", "cases/0/stdout"]:
            with self.subTest(path=path):
                previous = (self.root / path).read_bytes()
                (self.root / path).write_bytes(previous + b" ")
                with self.assertRaises(ValueError):
                    verify_packet(self.root)
                (self.root / path).write_bytes(previous)

    def test_rehashed_inconsistent_report(self):
        self.report["levels"]["0"]["passed"] = 2
        self.record["report"] = self.put("report.json", encoded(self.report))
        self.save()
        with self.assertRaises(ValueError):
            verify_packet(self.root)

    def test_missing_duplicate_and_foreign_terminal_records(self):
        original = copy.deepcopy(self.record)
        for cases in [[], self.record["cases"] * 2, [{**self.record["cases"][0], "case_id": "foreign"}]]:
            self.record = copy.deepcopy(original)
            self.record["cases"] = cases
            self.save()
            with self.assertRaises(ValueError):
                verify_packet(self.root)

    def test_duplicate_or_missing_result_slots(self):
        self.record["planned"][0]["slots"] *= 2
        self.save()
        with self.assertRaises(ValueError):
            verify_packet(self.root)

    def test_rehashed_stale_response(self):
        response = json.loads((self.root / "cases/0/stdout").read_bytes())
        response["run_id"] = "old-run"
        self.record["cases"][0]["stdout"] = self.put("cases/0/stdout", encoded(response))
        self.save()
        with self.assertRaises(ValueError):
            verify_packet(self.root)

    def test_request_binds_exact_input_bytes_not_only_decoded_values(self):
        # Whitespace changes preserve the decoded value but not its wire hash.
        request = (self.root / "cases/0/request.json").read_bytes()
        request = request.replace(b'"input":{"policy":', b'"input":{ "policy":')
        self.record["cases"][0]["request"] = self.put("cases/0/request.json", request)
        self.save()
        with self.assertRaises(ValueError):
            verify_packet(self.root)

    def test_symlink_artifact_is_not_a_verified_copy(self):
        path = self.root / "images/engine"
        path.rename(self.root / "moved")
        path.symlink_to(self.root / "moved")
        with self.assertRaises(ValueError):
            verify_packet(self.root)

    def test_packet_json_rejects_nonfinite_and_excessive_depth(self):
        for raw in [b'{"value":1e400}', b'[' * 65 + b'0' + b']' * 65, b'{"value":1,"value":2}']:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                strict_json(raw)


if __name__ == "__main__":
    unittest.main()

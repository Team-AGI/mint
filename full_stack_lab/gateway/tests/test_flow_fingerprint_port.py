"""The Rust fingerprint (fast-anything port) answers exactly as the Python original."""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = [("", b"s"), ("짧음", b"s"), ("Ａｂｃ①² ＡＢＣ 결재 문서 번호 2026-1125-0042 kim.minsu@corp.example " * 20, b"\x01" * 16),
         ("İstanbul ß ﬁ Ǆ ́ë \ud800 tail " * 30, b"salt"), ("x" * 5000, b"")]
PROBE = """
import json, sys
from app import flow_fingerprint as f
out = {"rust": type(f.fingerprint).__name__ == "builtin_function_or_method", "results": []}
for text, salt in json.loads(sys.argv[1]):
    salt = salt.encode("latin-1")
    try:
        out["results"].append(f.fingerprint(text, salt, 40000))
    except ValueError as exc:
        out["results"].append(str(exc))
try:
    f.fingerprint("a" * 100, b"s", 10)
except ValueError as exc:
    out["results"].append(str(exc))
print(json.dumps(out))
"""


def run(disable: bool) -> dict:
    env = {**os.environ, "FLOW_FINGERPRINT_PEPPER": "pepper"}
    env.pop("FAST_ANYTHING_DISABLE", None)
    if disable:
        env["FAST_ANYTHING_DISABLE"] = "1"
    cases = json.dumps([(t, s.decode("latin-1")) for t, s in CASES])
    done = subprocess.run([sys.executable, "-c", PROBE, cases], cwd=ROOT, env=env, capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


class FingerprintPort(unittest.TestCase):
    def test_same_as_python(self):
        python, rust = run(True), run(False)
        self.assertFalse(python["rust"])
        if not rust["rust"]:
            self.skipTest("Rust port not built here (.fast/lib)")
        self.assertEqual(rust["results"], python["results"])


if __name__ == "__main__":
    unittest.main()

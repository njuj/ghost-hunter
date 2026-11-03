"""Real processes on real Windows: a harmless target plants one injection-shaped thing in itself
(tests/target.py) and ghost-hunter, from the outside and read-only, has to find exactly that."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
TARGET = Path(__file__).resolve().parent / "target.py"


@unittest.skipUnless(sys.platform == "win32", "live tests need Windows")
class Live(unittest.TestCase):
    def spawn(self, mode):
        p = subprocess.Popen([sys.executable, str(TARGET), mode], stdout=subprocess.PIPE, text=True)

        def stop():
            p.kill()
            p.wait()
            p.stdout.close()
        self.addCleanup(stop)
        line = p.stdout.readline().split()
        self.assertEqual(line[:1], ["ready"], f"target {mode} did not start")
        return p, dict(kv.split("=") for kv in line[1:])

    def scan(self, pid):
        from ghosthunter import collect
        from ghosthunter.analyze import analyze
        proc, lp = collect.snapshot(pid)
        with lp:
            return analyze(proc)

    def serious(self, findings):
        return [(f.rule, f.severity) for f in findings if f.severity in ("critical", "high")]

    def test_clean_process(self):
        p, _ = self.spawn("clean")
        self.assertEqual(self.serious(self.scan(p.pid)), [])

    def test_thread_in_private_memory(self):
        p, info = self.spawn("thread")
        found = [f for f in self.scan(p.pid) if f.rule == "thread-start"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "critical")
        self.assertEqual(found[0].address, int(info["addr"]))
        self.assertIn(info["tid"], found[0].detail)

    def test_reflectively_loaded_pe(self):
        p, info = self.spawn("pe")
        self.assertEqual(self.serious(self.scan(p.pid)), [("pe-in-memory", "critical")])

    def test_rwx_memory(self):
        p, _ = self.spawn("rwx")
        found = [(f.rule, f.severity) for f in self.scan(p.pid) if f.rule == "unbacked-exec"]
        self.assertEqual(found, [("unbacked-exec", "medium")])

    def test_inline_hook_into_private_memory(self):
        p, info = self.spawn("hook")
        found = self.scan(p.pid)
        self.assertEqual(self.serious(found), [("inline-hook", "critical")])
        self.assertIn("!Beep", found[0].detail)
        self.assertIn(f"{int(info['target']):#x}", found[0].detail)

    def test_import_table_hook(self):
        p, info = self.spawn("iat")
        found = self.scan(p.pid)
        self.assertEqual(self.serious(found), [("iat-hook", "critical")])
        self.assertIn("python.exe", found[0].title)

    def test_module_stomping(self):
        p, _ = self.spawn("stomp")
        found = self.scan(p.pid)
        self.assertEqual(self.serious(found), [("modified-code", "critical")])
        self.assertIn("dbghelp.dll", found[0].title)

    def test_cli_json_and_exit_code(self):
        p, _ = self.spawn("thread")
        r = subprocess.run([sys.executable, "-m", "ghosthunter", "--pid", str(p.pid), "--json"], cwd=ROOT,
                           capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(r.returncode, 1, r.stderr)
        report = json.loads(r.stdout)
        self.assertEqual(report["processes"][0]["pid"], p.pid)
        self.assertIn("thread-start", [f["rule"] for f in report["processes"][0]["findings"]])

    def test_cli_dump(self):
        import tempfile
        p, info = self.spawn("pe")
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run([sys.executable, "-m", "ghosthunter", "--pid", str(p.pid), "--dump", d, "--no-color"],
                               cwd=ROOT, capture_output=True, text=True, encoding="utf-8", env={**os.environ, "PYTHONIOENCODING": "utf-8"})
            self.assertEqual(r.returncode, 1, r.stderr)
            dumps = os.listdir(d)
            self.assertEqual(len(dumps), 1)
            self.assertTrue(Path(d, dumps[0]).read_bytes().startswith(b"MZ"))

    def test_whole_machine_scan_runs(self):
        r = subprocess.run([sys.executable, "-m", "ghosthunter", "--no-color", "--min-severity", "critical"], cwd=ROOT,
                           capture_output=True, text=True, encoding="utf-8", env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.assertIn(r.returncode, (0, 1), r.stderr)
        self.assertIn("processes", r.stdout)


if __name__ == "__main__":
    unittest.main()

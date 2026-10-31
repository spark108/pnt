import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[2] / "pnt.sh"


def function(script, name, body):
    updated, count = re.subn(r"(?ms)^" + name + r"\(\) \{.*?^\}", lambda _: name + "() {\n" + body + "\n}", script)
    if count != 1:
        raise AssertionError(name)
    return updated


class WorkerChecks(unittest.TestCase):
    def scenario(self, fail_pull=False, fail_dependencies=False, fail_start=False):
        with tempfile.TemporaryDirectory(prefix="pnt-worker-check-") as directory:
            root = Path(directory)
            source, commands = root / "source", root / "commands"
            source.mkdir()
            commands.mkdir()
            script = SOURCE.read_text()
            for old, new in (("/opt/pnt", str(root / "app")), ("/usr/local/bin/pnt", str(root / "pnt-link")),
                             ("/etc/systemd/system/pnt.service", str(root / "pnt.service")),
                             ("/var/lib/pnt/operations", str(root / "operations")),
                             ("/run/pnt-maintenance.lock", str(root / "maintenance.lock"))):
                script = script.replace(old, new)
            script = function(script, "configure_access", "    :")
            script = function(script, "save_source_dir", "    :")
            fresh = function(script, "install_dependencies", '    echo new-dependencies >> "$TRACE"\n    [ "${FAIL_DEPS:-0}" = 0 ]')
            old = function(script, "install_dependencies", '    echo old-dependencies >> "$TRACE"\n    return 77')
            (source / "pnt.sh").write_text(old)
            incoming = root / "incoming.sh"
            incoming.write_text(fresh)
            (source / "deploy").mkdir()
            (source / "deploy/pnt.service").write_text("updated-unit")
            (root / "pnt.service").write_text("old-unit")
            app = root / "app"
            app.mkdir()
            binary = '#!/bin/sh\necho "pnt $*" >> "$TRACE"\n[ "$*" != "node status --require-cluster" ]\n'
            (app / "pnt").write_text(binary)
            (app / "pnt").chmod(0o755)
            stubs = {
                "git": '#!/bin/sh\ncase "$3" in\n rev-parse) printf "%s\\n" "$2" ;;\n symbolic-ref) echo master ;;\n pull) echo pull >> "$TRACE"; [ "$FAIL_PULL" = 0 ] || exit 42; cp "$INCOMING" "$2/pnt.sh" ;;\nesac\n',
                "systemctl": '#!/bin/sh\necho "systemctl $*" >> "$TRACE"\nif [ "$FAIL_START" = 1 ] && [ "$1" = start ] && grep -q "# rebuilt" "$OLD_BIN"; then exit 50; fi\n',
                "sleep": '#!/bin/sh\nexit 0\n',
                "dotnet": '#!/bin/sh\necho build >> "$TRACE"\nwhile [ "$#" -gt 0 ]; do\n if [ "$1" = -o ]; then shift; mkdir -p "$1"; cp "$OLD_BIN" "$1/pnt"; echo "# rebuilt" >> "$1/pnt"; exit 0; fi\n shift\ndone\nexit 1\n'
            }
            for name, content in stubs.items():
                path = commands / name
                path.write_text(content)
                path.chmod(0o755)
            trace = root / "trace"
            env = dict(os.environ, PATH=str(commands) + ":" + os.environ["PATH"], TRACE=str(trace), INCOMING=str(incoming),
                       OLD_BIN=str(app / "pnt"), FAIL_PULL=str(int(fail_pull)), FAIL_DEPS=str(int(fail_dependencies)), FAIL_START=str(int(fail_start)))
            result = subprocess.run(["/bin/sh", str(source / "pnt.sh"), "_worker", "update", "test-event", "a" * 32], env=env, timeout=15)
            events = trace.read_text().splitlines()
            code = (root / "operations/test-event.result").read_text().strip()
            self.assertEqual(str(result.returncode), code)
            self.assertEqual(events.count("pull"), 1)
            self.assertNotIn("old-dependencies", events)
            if fail_pull:
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("systemctl stop pnt.service", events)
                self.assertEqual((app / "pnt").read_text(), binary)
            elif fail_dependencies:
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("new-dependencies", events)
                self.assertNotIn("build", events)
                self.assertIn("systemctl start pnt.service", events)
                self.assertEqual((app / "pnt").read_text(), binary)
            elif fail_start:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((app / "pnt").read_text(), binary)
                self.assertEqual((root / "pnt.service").read_text(), "old-unit")
                self.assertEqual(events.count("systemctl start pnt.service"), 2)
            else:
                self.assertEqual(result.returncode, 0)
                self.assertLess(events.index("pull"), events.index("systemctl stop pnt.service"))
                self.assertLess(events.index("new-dependencies"), events.index("build"))
                self.assertIn("pnt node update applied " + "a" * 32, events)
                self.assertNotIn("announce", "\n".join(events))
                self.assertIn("# rebuilt", (app / "pnt").read_text())
                self.assertEqual((root / "pnt.service").read_text(), "updated-unit")

    def test_updated_worker_installs_dependencies_and_preserves_event(self):
        self.scenario()

    def test_failed_pull_does_not_stop_service(self):
        self.scenario(fail_pull=True)

    def test_failed_dependency_setup_restores_service(self):
        self.scenario(fail_dependencies=True)

    def test_failed_start_restores_binary_unit_and_service(self):
        self.scenario(fail_start=True)


if __name__ == "__main__":
    unittest.main()

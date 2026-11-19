"""Namespace-scoping regression tests; no Mininet imports or real signals."""
import ast
import os
from pathlib import Path
import signal
import shlex
import tempfile
import time
import types
import unittest
from unittest import mock


class ServiceNamespaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proc = self.root / "proc"
        self.proc.mkdir()
        self.script = self.root / "project" / "health_service.py"
        self.script.parent.mkdir()
        self.script.write_text("# fixture\n")

        def mapped_path(value):
            return self.proc if str(value) == "/proc" else Path(value)

        self.env = {
            "Path": mapped_path, "os": os, "signal": signal,
            "shlex": shlex, "time": time,
            "SERVICE_SCRIPT": self.script,
            "network": types.SimpleNamespace(
                get=lambda name: types.SimpleNamespace(pid=100)
            ),
            "host_cmd": mock.Mock(),
        }
        source = Path(__file__).with_name("topo_large.py").read_text()
        tree = ast.parse(source)
        names = {
            "service_process_pids",
            "service_process_running",
            "apply_service_fault",
        }
        selected = ast.Module(
            body=[
                node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name in names
            ],
            type_ignores=[],
        )
        exec(compile(selected, "topo_large.py", "exec"), self.env)
        self.add_process(100, "net:[h2]", ["/bin/bash", "mininet:h2"])

    def add_process(self, pid, namespace, args):
        directory = self.proc / str(pid)
        (directory / "ns").mkdir(parents=True)
        (directory / "ns/net").symlink_to(namespace)
        (directory / "cwd").symlink_to(self.script.parent)
        (directory / "cmdline").write_bytes(
            b"\0".join(os.fsencode(arg) for arg in args) + b"\0"
        )

    def test_external_services_do_not_mark_h2_running(self):
        for pid, namespace in ((201, "net:[old]"), (202, "net:[host]")):
            self.add_process(pid, namespace, ["python3", str(self.script)])
        self.assertEqual(self.env["service_process_pids"](), [])
        self.assertFalse(self.env["service_process_running"]())

    def test_current_h2_service_is_found(self):
        self.add_process(203, "net:[h2]", ["python3", str(self.script)])
        self.assertEqual(self.env["service_process_pids"](), [203])

    def test_relative_script_and_unrelated_script(self):
        self.add_process(204, "net:[h2]", ["python3", "health_service.py"])
        self.add_process(
            205, "net:[h2]", ["python3", "/elsewhere/health_service.py"]
        )
        self.assertEqual(self.env["service_process_pids"](), [204])

    def test_stop_signals_only_scoped_pid(self):
        scoped = mock.Mock(return_value=[203])
        running = mock.Mock(return_value=False)
        self.env["service_process_pids"] = scoped
        self.env["service_process_running"] = running
        with mock.patch.object(os, "kill") as kill:
            result = self.env["apply_service_fault"]("enable")
        kill.assert_called_once_with(203, signal.SIGTERM)
        self.env["host_cmd"].assert_not_called()
        self.assertFalse(result["running"])

    def test_start_runs_on_h2_when_service_missing(self):
        self.env["service_process_running"] = mock.Mock(
            side_effect=[False, True, True]
        )
        result = self.env["apply_service_fault"]("disable")
        command = self.env["host_cmd"].call_args
        self.assertEqual(command.args[0], "h2")
        self.assertIn("nohup python3", command.args[1])
        self.assertTrue(result["running"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

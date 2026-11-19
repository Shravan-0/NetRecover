import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import topo_large


class ServiceConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config = Path(self.temp_dir.name) / "service.conf"
        self.original = topo_large.SERVICE_CONFIG
        topo_large.SERVICE_CONFIG = self.config

    def tearDown(self):
        topo_large.SERVICE_CONFIG = self.original
        self.temp_dir.cleanup()

    def test_write_healthy_config(self):
        result = topo_large.set_service_config("ok")
        self.assertEqual(result, "mode=ok")
        self.assertEqual(self.config.read_text(), "mode=ok\n")
        self.assertEqual(stat.S_IMODE(self.config.stat().st_mode), 0o644)

    def test_write_broken_config(self):
        result = topo_large.set_service_config("broken")
        self.assertEqual(result, "mode=broken")
        self.assertEqual(self.config.read_text(), "mode=broken\n")

    def test_invalid_mode_does_not_change_existing_config(self):
        self.config.write_text("mode=ok\n")
        with self.assertRaises(ValueError):
            topo_large.set_service_config("unexpected")
        self.assertEqual(self.config.read_text(), "mode=ok\n")

    def test_healthy_status(self):
        self.config.write_text("mode=ok\n")
        result = topo_large.service_config_status()
        self.assertEqual(result["state"], "ok")
        self.assertTrue(result["ok"])

    def test_fault_status(self):
        self.config.write_text("mode=broken\n")
        result = topo_large.service_config_status()
        self.assertEqual(result["state"], "fault")
        self.assertTrue(result["ok"])

    def test_unknown_status(self):
        self.config.write_text("mode=something-else\n")
        result = topo_large.service_config_status()
        self.assertEqual(result["state"], "unknown")
        self.assertTrue(result["ok"])

    def test_missing_file_is_unknown(self):
        result = topo_large.service_config_status()
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unknown")
        self.assertIn("error", result)

    def test_temporary_files_are_cleaned_up(self):
        topo_large.set_service_config("broken")
        leftovers = list(Path(self.temp_dir.name).glob(".acn-service-config-*"))
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

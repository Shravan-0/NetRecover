import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import topo_large


class ConfigControlAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            topo_large.ControlHandler,
        )
        cls.thread = threading.Thread(
            target=cls.server.serve_forever,
            daemon=True,
        )
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config = Path(self.temp_dir.name) / "service.conf"
        self.config.write_text("mode=ok\n")
        self.original_config = topo_large.SERVICE_CONFIG
        topo_large.SERVICE_CONFIG = self.config
        self.invalidate = mock.patch.object(
            topo_large.SYSTEM_HEALTH,
            "invalidate",
        )
        self.mock_invalidate = self.invalidate.start()

    def tearDown(self):
        self.invalidate.stop()
        topo_large.SERVICE_CONFIG = self.original_config
        self.temp_dir.cleanup()

    def request(self, method, path, payload=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=3
        )
        body = None if payload is None else json.dumps(payload)
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        status = response.status
        data = response.read()
        connection.close()
        return status, json.loads(data.decode("utf-8"))

    def test_enable_config_fault(self):
        status, body = self.request(
            "POST", "/api/config", {"action": "enable"}
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["state"], "fault")
        self.assertEqual(body["config"], "mode=broken")
        self.assertEqual(self.config.read_text(), "mode=broken\n")
        self.mock_invalidate.assert_called_once_with()

    def test_disable_config_fault(self):
        self.config.write_text("mode=broken\n")
        status, body = self.request(
            "POST", "/api/config", {"action": "disable"}
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["state"], "ok")
        self.assertEqual(body["config"], "mode=ok")
        self.assertEqual(self.config.read_text(), "mode=ok\n")
        self.mock_invalidate.assert_called_once_with()

    def test_get_config_status(self):
        status, body = self.request("GET", "/api/config/status")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["state"], "ok")

    def test_invalid_action_returns_400_without_write(self):
        status, body = self.request(
            "POST", "/api/config", {"action": "restart"}
        )
        self.assertEqual(status, 400)
        self.assertFalse(body["ok"])
        self.assertEqual(self.config.read_text(), "mode=ok\n")
        self.mock_invalidate.assert_not_called()

    def test_malformed_json_returns_400_without_write(self):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=3
        )
        connection.request(
            "POST",
            "/api/config",
            body="{not-json",
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        status = response.status
        body = json.loads(response.read().decode("utf-8"))
        connection.close()

        self.assertEqual(status, 400)
        self.assertFalse(body["ok"])
        self.assertEqual(self.config.read_text(), "mode=ok\n")
        self.mock_invalidate.assert_not_called()

    def test_missing_config_returns_503(self):
        self.config.unlink()
        status, body = self.request("GET", "/api/config/status")
        self.assertEqual(status, 503)
        self.assertFalse(body["ok"])
        self.assertEqual(body["state"], "unknown")


if __name__ == "__main__":
    unittest.main(verbosity=2)

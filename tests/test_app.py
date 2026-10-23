import hashlib
import json
import os
import socket
import errno
import tempfile
import unittest
from unittest.mock import patch

import app as portmonitor


class PortMonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        with portmonitor._LOGIN_LOCK:
            portmonitor._LOGIN_ATTEMPTS.clear()
        self.original_paths = (
            portmonitor.USERS_FILE,
            portmonitor.MACHINES_FILE,
            portmonitor.SESSIONS_FILE,
        )
        portmonitor.USERS_FILE = os.path.join(self.temp_dir.name, "users.json")
        portmonitor.MACHINES_FILE = os.path.join(self.temp_dir.name, "machines.json")
        portmonitor.SESSIONS_FILE = os.path.join(self.temp_dir.name, "sessions.json")
        portmonitor.app.config.update(TESTING=True)
        self.client = portmonitor.app.test_client()

    def tearDown(self):
        (
            portmonitor.USERS_FILE,
            portmonitor.MACHINES_FILE,
            portmonitor.SESSIONS_FILE,
        ) = self.original_paths
        self.temp_dir.cleanup()

    def test_registration_enforces_password_policy_and_hashes_password(self):
        short = self.client.post(
            "/api/register",
            json={"username": "test-user", "password": "short"},
        )
        self.assertEqual(short.status_code, 400)

        response = self.client.post(
            "/api/register",
            json={"username": "test-user", "password": "long-test-password"},
        )
        self.assertEqual(response.status_code, 200)
        with open(portmonitor.USERS_FILE, encoding="utf-8") as data_file:
            record = json.load(data_file)["test-user"]
        self.assertTrue(record["password"].startswith("scrypt:"))
        self.assertNotEqual(record["password"], hashlib.sha256(b"long-test-password").hexdigest())

    def test_legacy_password_hash_is_upgraded_on_successful_login(self):
        legacy_password = "legacy-password"
        with open(portmonitor.USERS_FILE, "w", encoding="utf-8") as data_file:
            json.dump({
                "legacy-user": {
                    "password": hashlib.sha256(legacy_password.encode()).hexdigest(),
                    "created": "2026-01-01T00:00:00",
                }
            }, data_file)

        response = self.client.post(
            "/api/login",
            json={"username": "legacy-user", "password": legacy_password},
        )
        self.assertEqual(response.status_code, 200)
        with open(portmonitor.USERS_FILE, encoding="utf-8") as data_file:
            upgraded = json.load(data_file)["legacy-user"]["password"]
        self.assertTrue(upgraded.startswith("scrypt:"))

    def test_login_stores_only_hashed_session_token_and_logout_revokes_it(self):
        password = "long-test-password"
        with open(portmonitor.USERS_FILE, "w", encoding="utf-8") as data_file:
            json.dump({
                "test-user": {
                    "password": portmonitor.hash_pw(password),
                    "created": portmonitor.utcnow().isoformat(),
                }
            }, data_file)

        login = self.client.post(
            "/api/login",
            json={"username": "test-user", "password": password},
        )
        token = login.get_json()["token"]
        with open(portmonitor.SESSIONS_FILE, encoding="utf-8") as data_file:
            sessions = json.load(data_file)
        self.assertIn(portmonitor.token_key(token), sessions)
        self.assertNotIn(token, sessions)
        self.assertEqual(portmonitor.verify_token(token), "test-user")

        logout = self.client.post("/api/logout", headers={"X-Token": token})
        self.assertEqual(logout.status_code, 200)
        self.assertIsNone(portmonitor.verify_token(token))

    def test_legacy_session_key_is_upgraded_when_verified(self):
        legacy_token = "legacy-session-token"
        with open(portmonitor.SESSIONS_FILE, "w", encoding="utf-8") as data_file:
            json.dump({
                legacy_token: {
                    "username": "legacy-user",
                    "expires": (portmonitor.utcnow() + portmonitor.timedelta(hours=1)).isoformat(),
                }
            }, data_file)

        self.assertEqual(portmonitor.verify_token(legacy_token), "legacy-user")
        with open(portmonitor.SESSIONS_FILE, encoding="utf-8") as data_file:
            sessions = json.load(data_file)
        self.assertNotIn(legacy_token, sessions)
        self.assertIn(portmonitor.token_key(legacy_token), sessions)

    def test_host_and_scan_configuration_are_validated(self):
        self.assertEqual(
            portmonitor.validate_scan_config(
                {"host": "127.0.0.1", "start": 1, "end": 1024, "timeout": 0.5},
                "tcp",
            ),
            ("127.0.0.1", 1, 1024, 0.5, 500),
        )
        for host in ("https://example.com", "127.0.0.1:443", "bad host", "::1"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                portmonitor.validate_host(host)
        for config in (
            {"host": "127.0.0.1", "start": 0, "end": 1},
            {"host": "127.0.0.1", "start": 100, "end": 1},
            {"host": "127.0.0.1", "start": 1.5, "end": 2},
            {"host": "127.0.0.1", "start": 1, "end": 2, "timeout": 5},
            {"host": "127.0.0.1", "start": 1, "end": 2, "batch": 501},
        ):
            with self.subTest(config=config), self.assertRaises(ValueError):
                portmonitor.validate_scan_config(config, "tcp")
        with patch.dict(os.environ, {"PORTMONITOR_ALLOWED_TARGETS": "192.0.2.0/24"}):
            with self.assertRaisesRegex(ValueError, "not in PORTMONITOR_ALLOWED_TARGETS"):
                portmonitor.validate_host("127.0.0.1")

    def test_open_tcp_result_does_not_claim_internet_exposure(self):
        with (
            patch.object(portmonitor, "_tcp_connect", return_value={"status": "open"}),
            patch.object(
                portmonitor,
                "grab_banner",
                return_value=(b"SSH-2.0-OpenSSH_9", "SSH-2.0-OpenSSH_9"),
            ),
        ):
            result = portmonitor.scan_port("127.0.0.1", 22)
        self.assertEqual(result["status"], "open")
        self.assertEqual(result["service"], "ssh")
        self.assertIsNone(result["exposed"])

    def test_tcp_refusal_is_closed_but_other_failures_are_filtered(self):
        fake_socket = unittest.mock.MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        fake_socket.connect_ex.return_value = errno.ECONNREFUSED
        with patch.object(portmonitor.socket, "socket", return_value=fake_socket):
            result = portmonitor._tcp_connect("127.0.0.1", 12345, 0.1)
        self.assertEqual(result["status"], "closed")

        fake_socket.connect_ex.return_value = 10060
        with patch.object(portmonitor.socket, "socket", return_value=fake_socket):
            result = portmonitor._tcp_connect("127.0.0.1", 12345, 0.1)
        self.assertEqual(result["status"], "filtered")

    def test_udp_timeout_is_reported_as_uncertain_not_confirmed_open(self):
        fake_socket = unittest.mock.MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        fake_socket.recvfrom.side_effect = socket.timeout
        with patch.object(portmonitor.socket, "socket", return_value=fake_socket):
            result = portmonitor.scan_udp_port("127.0.0.1", 53535, timeout=0.1)
        self.assertEqual(result["status"], "open|filtered")
        self.assertIsNone(result["exposed"])

    def test_corrupt_json_is_reported_instead_of_silently_defaulting(self):
        path = os.path.join(self.temp_dir.name, "broken.json")
        with open(path, "w", encoding="utf-8") as data_file:
            data_file.write("{not valid JSON")
        with self.assertRaises(RuntimeError):
            portmonitor.load_json(path, {})

    def test_machine_api_rejects_invalid_target_before_saving(self):
        with patch.object(portmonitor, "verify_token", return_value="alice"):
            response = self.client.post(
                "/api/machines",
                headers={"X-Token": "test-token"},
                json={"name": "Target", "host": "http://127.0.0.1"},
            )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(os.path.exists(portmonitor.MACHINES_FILE))


if __name__ == "__main__":
    unittest.main()

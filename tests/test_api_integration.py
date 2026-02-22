import importlib
import os
import sys
import tempfile
import time
import unittest


class FlashNoteApiIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._old_env = dict(os.environ)
        cls._tmp_home = tempfile.TemporaryDirectory(prefix="flash-note-test-home-")
        os.environ["HOME"] = cls._tmp_home.name
        os.environ["APP_ENV"] = "dev"
        os.environ["APP_STORAGE_BACKEND"] = "sqlite"
        os.environ["APP_LOGIN_USERNAME"] = "ci_user"
        os.environ["APP_LOGIN_PASSWORD"] = "ci_pass"
        os.environ["APP_AUTH_BOOTSTRAP_SYNC_MODE"] = "sync"
        os.environ["SESSION_COOKIE_SECURE"] = "0"

        backend_dir = "/root/flash-note/backend"
        if backend_dir not in sys.path:
            sys.path.insert(0, backend_dir)
        cls.app_module = importlib.import_module("app")

    @classmethod
    def tearDownClass(cls):
        os.environ.clear()
        os.environ.update(cls._old_env)
        cls._tmp_home.cleanup()

    def setUp(self):
        self.client = self.app_module.app.test_client()

    def login(self):
        resp = self.client.post(
            "/api/auth/login",
            json={"username": "ci_user", "password": "ci_pass"},
        )
        self.assertEqual(resp.status_code, 200, msg=resp.get_data(as_text=True))

    def _ensure_user(self, username: str, password: str, role: str):
        payload = self.app_module.read_users_store()
        users = payload.get("users", [])
        target = username.strip().lower()
        user = next(
            (u for u in users if str(u.get("username", "")).strip().lower() == target),
            None,
        )
        if user is None:
            now_iso = self.app_module.now_utc_iso()
            users.append(
                {
                    "username": username,
                    "passwordHash": self.app_module.hash_password_pbkdf2(password),
                    "status": "active",
                    "role": role,
                    "createdAt": now_iso,
                    "updatedAt": now_iso,
                }
            )
        else:
            user["passwordHash"] = self.app_module.hash_password_pbkdf2(password)
            user["status"] = "active"
            user["role"] = role
            user["updatedAt"] = self.app_module.now_utc_iso()
        self.app_module.write_json_file(self.app_module.USERS_FILE, {"version": 1, "users": users})

    def test_public_healthz_minimal_payload(self):
        resp = self.client.get("/healthz")
        self.assertEqual(resp.status_code, 200, msg=resp.get_data(as_text=True))
        payload = resp.get_json()
        self.assertEqual(payload, {"status": "ok"})

    def test_internal_healthz_requires_login(self):
        resp = self.client.get("/api/admin/healthz/internal")
        self.assertEqual(resp.status_code, 401, msg=resp.get_data(as_text=True))

    def test_internal_healthz_contains_diagnostics_after_login(self):
        self.login()
        resp = self.client.get("/api/admin/healthz/internal")
        self.assertEqual(resp.status_code, 200, msg=resp.get_data(as_text=True))
        payload = resp.get_json()
        self.assertEqual(payload.get("status"), "ok")
        self.assertIn("env", payload)
        self.assertIn("uptimeSec", payload)
        self.assertIn("storageBackend", payload)
        self.assertIn("authStore", payload)
        self.assertIn("notesCache", payload)

    def test_internal_healthz_forbidden_for_non_admin(self):
        self._ensure_user("ci_user2", "ci_pass2", role="user")
        login_resp = self.client.post(
            "/api/auth/login",
            json={"username": "ci_user2", "password": "ci_pass2"},
        )
        self.assertEqual(login_resp.status_code, 200, msg=login_resp.get_data(as_text=True))
        resp = self.client.get("/api/admin/healthz/internal")
        self.assertEqual(resp.status_code, 403, msg=resp.get_data(as_text=True))

    def test_request_id_echo_header(self):
        request_id = "ci-req-id-001"
        resp = self.client.get("/healthz", headers={"X-Request-ID": request_id})
        self.assertEqual(resp.status_code, 200, msg=resp.get_data(as_text=True))
        self.assertEqual(resp.headers.get("X-Request-ID"), request_id)

    def test_session_expires_after_idle_timeout(self):
        self.login()
        alive_resp = self.client.get("/api/categories")
        self.assertEqual(alive_resp.status_code, 200, msg=alive_resp.get_data(as_text=True))

        with self.client.session_transaction() as sess:
            sess["last_activity_ts"] = time.time() - (
                self.app_module.APP_SESSION_IDLE_TIMEOUT_SEC + 5
            )

        expired_resp = self.client.get("/api/categories")
        self.assertEqual(
            expired_resp.status_code, 401, msg=expired_resp.get_data(as_text=True)
        )

        status_resp = self.client.get("/api/auth/status")
        self.assertEqual(status_resp.status_code, 200, msg=status_resp.get_data(as_text=True))
        payload = status_resp.get_json() or {}
        self.assertFalse(payload.get("loggedIn", True))


if __name__ == "__main__":
    unittest.main(verbosity=2)

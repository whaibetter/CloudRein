import hashlib
import io
import ipaddress
import json
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


_TEST_ROOT = tempfile.TemporaryDirectory(prefix="cloudrein-test-")
_ROOT = Path(_TEST_ROOT.name)
_CONFIG_FILE = _ROOT / "config.yaml"
_USER_CONFIG_FILE = _ROOT / "user_config.yaml"
_DATA_DIR = _ROOT / "data"
_WORK_DIR = _ROOT / "work"
_SECRET = "11" * 32

_CONFIG_FILE.write_text(
    "security:\n"
    "  delete_whitelist:\n"
    f"    - {_WORK_DIR}\n"
    "permissions:\n"
    "  default_permissions:\n"
    "    read: true\n"
    "    write: true\n"
    "  folder_permissions: {}\n",
    encoding="utf-8",
)
os.environ["CLOUDREIN_CONFIG_FILE"] = str(_CONFIG_FILE)
os.environ["CLOUDREIN_USER_CONFIG_FILE"] = str(_USER_CONFIG_FILE)
os.environ["CLOUDREIN_DATA_DIR"] = str(_DATA_DIR)
os.environ["JD_SSO_SECRET"] = _SECRET
os.environ["JD_SSO_SECRET_FILE"] = str(_ROOT / "missing-sso.key")
os.environ["CLOUDREIN_SSO_APP_ID"] = "webdav"

from server import create_app
from server import auth, session
from server.sso import SsoVerifier


class CloudReinSecurityTests(unittest.TestCase):
    password = "correct horse battery staple"

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config.update(TESTING=True)
        cls.verifier = SsoVerifier(secret=_SECRET)

    def setUp(self):
        _WORK_DIR.mkdir(parents=True, exist_ok=True)
        auth.PASSWORD_FILE.parent.mkdir(parents=True, exist_ok=True)
        auth.PASSWORD_FILE.write_text(
            hashlib.sha256(self.password.encode("utf-8")).hexdigest() + "\n",
            encoding="ascii",
        )
        auth.PASSWORD_FILE.chmod(0o600)
        with session._sessions_lock:
            session.sessions.clear()
        with auth._login_failures_lock:
            auth._login_failures.clear()
        self.client = self.app.test_client()

    def login(self, client=None, password=None):
        client = client or self.client
        response = client.post(
            "/api/login",
            json={"password": self.password if password is None else password},
            base_url="https://localhost",
            headers={"Origin": "https://localhost"},
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        data = client.get("/api/session", base_url="https://localhost").get_json()
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["authType"], "local")
        self.assertTrue(data["csrf"])
        return data["csrf"]

    def sso_client(self):
        client = self.app.test_client()
        token = self.verifier.sign_session("webdav", 300)
        client.set_cookie("jd_sso", token, domain="localhost")
        data = client.get("/api/session", base_url="https://localhost").get_json()
        self.assertEqual(data["authType"], "sso")
        self.assertEqual(data["csrf"], self.verifier.csrf_for(token))
        return client, token, data["csrf"]

    def write(self, path, client=None, csrf="", **kwargs):
        client = client or self.client
        headers = {"Origin": "https://localhost"}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        return client.post(
            path, base_url="https://localhost", headers=headers, **kwargs
        )

    def test_session_is_unauthenticated_without_cookie(self):
        response = self.client.get("/api/session", base_url="https://localhost")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"authenticated": False, "authType": "", "csrf": ""},
        )

    def test_public_health_is_lightweight_and_unauthenticated(self):
        response = self.client.get("/api/health", base_url="https://localhost")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"ok": True})

    def test_every_api_write_requires_csrf(self):
        csrf = self.login()
        routes = set()
        for rule in self.app.url_map.iter_rules():
            if not rule.rule.startswith("/api/") or rule.rule == "/api/login":
                continue
            for method in rule.methods - {"GET", "HEAD", "OPTIONS"}:
                routes.add((rule.rule, method))
        self.assertTrue(routes)
        for path, method in sorted(routes):
            with self.subTest(path=path, method=method):
                response = self.client.open(
                    path,
                    method=method,
                    base_url="https://localhost",
                    headers={"Origin": "https://localhost"},
                )
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.get_json(), {"error": "csrf"})
        self.assertNotEqual(csrf, "")

    def test_every_api_write_requires_authentication(self):
        for path, method in sorted({
            (rule.rule, method)
            for rule in self.app.url_map.iter_rules()
            if rule.rule.startswith("/api/") and rule.rule != "/api/login"
            for method in rule.methods - {"GET", "HEAD", "OPTIONS"}
        }):
            with self.subTest(path=path, method=method):
                response = self.client.open(
                    path,
                    method=method,
                    base_url="https://localhost",
                    headers={"Origin": "https://localhost", "X-CSRF-Token": "x"},
                )
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.get_json(), {"error": "Unauthorized"})

    def test_cross_origin_null_and_malformed_origins_are_rejected(self):
        csrf = self.login()
        for origin in (
            "https://evil.example",
            "null",
            "http://localhost",
            "https://localhost:444",
            "https://user@localhost",
            "http://[broken",
            "https://localhost/path",
        ):
            with self.subTest(origin=origin):
                response = self.client.post(
                    "/api/quickpaths",
                    json={"quick_paths": []},
                    base_url="https://localhost",
                    headers={"Origin": origin, "X-CSRF-Token": csrf},
                )
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.get_json(), {"error": "origin"})

    def test_missing_origin_only_allows_explicit_native_client(self):
        csrf = self.login()
        response = self.client.post(
            "/api/quickpaths",
            json={"quick_paths": []},
            base_url="https://localhost",
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json(), {"error": "origin"})

        response = self.client.post(
            "/api/quickpaths",
            json={"quick_paths": []},
            base_url="https://localhost",
            headers={"X-CSRF-Token": csrf, "X-CloudRein-Client": "native"},
        )
        self.assertEqual(response.status_code, 200)

    def test_login_rejects_cross_origin_but_accepts_native(self):
        for headers in ({"Origin": "https://evil.example"}, {"Origin": "null"}):
            response = self.client.post(
                "/api/login",
                json={"password": self.password},
                base_url="https://localhost",
                headers=headers,
            )
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.get_json(), {"error": "origin"})
        response = self.client.post(
            "/api/login",
            json={"password": self.password},
            base_url="https://localhost",
            headers={"X-CloudRein-Client": "native"},
        )
        self.assertEqual(response.status_code, 200)

    def test_valid_csrf_allows_write_and_wrong_csrf_is_rejected(self):
        csrf = self.login()
        response = self.write(
            "/api/quickpaths", csrf=csrf, json={"quick_paths": []}
        )
        self.assertEqual(response.status_code, 200)
        response = self.write(
            "/api/quickpaths", csrf="wrong", json={"quick_paths": []}
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json(), {"error": "csrf"})

    def test_sso_csrf_allows_write(self):
        client, _, csrf = self.sso_client()
        response = self.write(
            "/api/quickpaths", client=client, csrf=csrf, json={"quick_paths": []}
        )
        self.assertEqual(response.status_code, 200)
        response = self.write(
            "/api/quickpaths", client=client, json={"quick_paths": []}
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json(), {"error": "csrf"})

    def test_forwarded_origin_is_ignored_from_untrusted_peer(self):
        csrf = self.login()
        response = self.client.post(
            "/api/quickpaths",
            json={"quick_paths": []},
            base_url="https://localhost",
            headers={
                "Origin": "https://webdav.example",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "webdav.example",
                "X-CSRF-Token": csrf,
            },
            environ_overrides={"REMOTE_ADDR": "203.0.113.10"},
        )
        self.assertEqual(response.status_code, 403)

    def test_forwarded_origin_matches_only_for_explicitly_trusted_proxy(self):
        csrf = self.login()
        with patch.object(session, "TRUSTED_PROXIES", [ipaddress.ip_network("203.0.113.0/24")]):
            response = self.client.post(
                "/api/quickpaths",
                json={"quick_paths": []},
                base_url="https://localhost",
                headers={
                    "Origin": "https://webdav.example",
                    "X-Forwarded-Proto": "https",
                    "X-Forwarded-Host": "webdav.example",
                    "X-CSRF-Token": csrf,
                },
                environ_overrides={"REMOTE_ADDR": "203.0.113.10"},
            )
        self.assertEqual(response.status_code, 200)

    def test_login_rate_limit_blocks_eleventh_attempt(self):
        for _ in range(auth.LOGIN_FAILURE_LIMIT):
            response = self.client.post(
                "/api/login",
                json={"password": "wrong"},
                base_url="https://localhost",
                headers={"Origin": "https://localhost"},
            )
            self.assertEqual(response.status_code, 401)
        response = self.client.post(
            "/api/login",
            json={"password": self.password},
            base_url="https://localhost",
            headers={"Origin": "https://localhost"},
        )
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["Retry-After"], "600")

    def test_successful_login_clears_failures(self):
        for _ in range(3):
            self.client.post(
                "/api/login",
                json={"password": "wrong"},
                base_url="https://localhost",
                headers={"Origin": "https://localhost"},
            )
        self.login()
        self.assertFalse(auth.login_rate_limited("127.0.0.1"))

    def test_rate_limit_expires_after_window(self):
        now = time.monotonic()
        with auth._login_failures_lock:
            auth._login_failures["127.0.0.1"] = [
                now - auth.LOGIN_FAILURE_WINDOW - 1
            ] * auth.LOGIN_FAILURE_LIMIT
        self.assertFalse(auth.login_rate_limited("127.0.0.1"))

    def test_client_ip_only_trusts_forwarded_header_from_loopback(self):
        with self.app.test_request_context(
            "/", environ_base={"REMOTE_ADDR": "127.0.0.1"},
            headers={"X-Forwarded-For": "198.51.100.1, 127.0.0.1"},
        ):
            self.assertEqual(session.client_ip(), "127.0.0.1")
        with self.app.test_request_context(
            "/", environ_base={"REMOTE_ADDR": "203.0.113.5"},
            headers={"X-Forwarded-For": "198.51.100.99"},
        ):
            self.assertEqual(session.client_ip(), "203.0.113.5")

    def test_legacy_password_upgrades_to_scrypt_with_private_permissions(self):
        self.login()
        stored = auth.PASSWORD_FILE.read_text(encoding="ascii").strip()
        self.assertTrue(stored.startswith(auth.SCRYPT_PREFIX))
        self.assertEqual(len(stored.split("$")), 6)
        self.assertEqual(stat.S_IMODE(auth.PASSWORD_FILE.stat().st_mode), 0o600)
        self.assertTrue(auth.verify_password(self.password))
        self.assertFalse(auth.verify_password("wrong"))

    def test_scrypt_hashes_use_random_salts(self):
        first = auth.hash_password(self.password)
        second = auth.hash_password(self.password)
        self.assertNotEqual(first, second)
        auth.PASSWORD_FILE.write_text(first + "\n", encoding="ascii")
        self.assertTrue(auth.verify_password(self.password))

    def test_new_password_requires_twelve_characters(self):
        success, _ = auth.change_password(self.password, "x" * 11)
        self.assertFalse(success)
        success, _ = auth.change_password(self.password, "x" * 12)
        self.assertTrue(success)
        self.assertTrue(auth.verify_password("x" * 12))

    def test_https_login_and_logout_cookies_are_secure(self):
        response = self.client.post(
            "/api/login",
            json={"password": self.password},
            base_url="https://localhost",
            headers={"Origin": "https://localhost"},
        )
        cookies = response.headers.getlist("Set-Cookie")
        self.assertTrue(any("sessionid=" in value and "Secure" in value for value in cookies))
        csrf = self.client.get(
            "/api/session", base_url="https://localhost"
        ).get_json()["csrf"]
        response = self.write("/api/logout", csrf=csrf)
        cookies = response.headers.getlist("Set-Cookie")
        self.assertTrue(any("sessionid=" in value and "Secure" in value for value in cookies))
        self.assertTrue(any("jd_sso=" in value and "Secure" in value for value in cookies))

    def test_http_login_cookie_is_not_secure(self):
        response = self.client.post(
            "/api/login",
            json={"password": self.password},
            base_url="http://localhost",
            headers={"Origin": "http://localhost"},
        )
        cookie = next(
            value for value in response.headers.getlist("Set-Cookie")
            if value.startswith("sessionid=")
        )
        self.assertNotIn("Secure", cookie)

    def test_ticket_replay_grace_is_90_seconds_and_checks_audience(self):
        now = [1_700_000_000]
        verifier = SsoVerifier(
            secret=_SECRET, cache_seconds=0, clock=lambda: now[0]
        )
        ticket = verifier.sign_payload({
            "v": 1, "typ": "ticket", "iss": "jd-auth", "aud": "webdav",
            "iat": now[0], "exp": now[0] + 120, "jti": "grace-boundary",
        })
        first = verifier.verify_ticket(ticket, "webdav")
        self.assertTrue(first.ok)
        self.assertFalse(first.replay)
        self.assertEqual(verifier.verify_ticket(ticket, "other").reason, "audience")
        now[0] += 90
        replay = verifier.verify_ticket(ticket, "webdav")
        self.assertTrue(replay.ok)
        self.assertTrue(replay.replay)
        now[0] += 1
        rejected = verifier.verify_ticket(ticket, "webdav")
        self.assertFalse(rejected.ok)
        self.assertEqual(rejected.reason, "replay")

    def test_ticket_replay_never_crosses_exp(self):
        now = [1_700_000_000]
        verifier = SsoVerifier(
            secret=_SECRET, cache_seconds=0, clock=lambda: now[0]
        )
        ticket = verifier.sign_payload({
            "v": 1, "typ": "ticket", "iss": "jd-auth", "aud": "webdav",
            "iat": now[0], "exp": now[0] + 30, "jti": "expiry-boundary",
        })
        self.assertTrue(verifier.verify_ticket(ticket, "webdav").ok)
        now[0] += 29
        self.assertTrue(verifier.verify_ticket(ticket, "webdav").replay)
        now[0] += 1
        expired = verifier.verify_ticket(ticket, "webdav")
        self.assertFalse(expired.ok)
        self.assertEqual(expired.reason, "expired")

    def test_ticket_replay_can_be_disabled(self):
        now = [1_700_000_000]
        verifier = SsoVerifier(
            secret=_SECRET, cache_seconds=0, ticket_replay_grace_sec=0,
            clock=lambda: now[0],
        )
        ticket = verifier.sign_payload({
            "v": 1, "typ": "ticket", "iss": "jd-auth", "aud": "webdav",
            "iat": now[0], "exp": now[0] + 120, "jti": "strict-ticket",
        })
        self.assertTrue(verifier.verify_ticket(ticket, "webdav").ok)
        self.assertEqual(verifier.verify_ticket(ticket, "webdav").reason, "replay")

    def test_ticket_exchange_sets_secure_cookies(self):
        now = int(time.time())
        ticket = self.verifier.sign_payload({
            "v": 1, "typ": "ticket", "iss": "jd-auth", "aud": "webdav",
            "sub": "owner", "iat": now, "exp": now + 60, "jti": "test-ticket",
        })
        response = self.client.get(
            "/?jd_ticket=" + ticket + "&return=%2Ffiles",
            base_url="https://localhost",
        )
        self.assertEqual(response.status_code, 302)
        cookies = response.headers.getlist("Set-Cookie")
        self.assertTrue(any(value.startswith("sessionid=") and "Secure" in value for value in cookies))
        self.assertTrue(any(value.startswith("jd_sso=") and "Secure" in value for value in cookies))
        self.assertEqual(response.location, "/?return=%2Ffiles")
        self.assertNotIn("jd_ticket=", response.location)

    def test_route_exception_does_not_leak_details(self):
        csrf = self.login()
        target = _WORK_DIR / "private.txt"
        target.write_text("before", encoding="utf-8")
        with patch(
            "server.routes.files.shutil.copy2",
            side_effect=OSError("secret filesystem detail"),
        ):
            with self.assertLogs(self.app.logger, level="ERROR"):
                response = self.write(
                    "/api/file/save",
                    csrf=csrf,
                    json={"path": str(_WORK_DIR / "private.txt"), "content": "x"},
                )
        self.assertEqual(response.status_code, 500)
        body = response.get_data(as_text=True)
        self.assertIn("Internal server error", body)
        self.assertNotIn("secret filesystem detail", body)

    def test_zip_is_removed_when_response_closes(self):
        csrf = self.login()
        folder = _WORK_DIR / "download"
        folder.mkdir(exist_ok=True)
        (folder / "hello.txt").write_text("hello", encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="cloudrein-zip-") as zip_dir:
            with patch("tempfile.tempdir", zip_dir):
                response = self.client.get(
                    "/api/file/download",
                    query_string={"path": str(folder)},
                    base_url="https://localhost",
                )
                self.assertEqual(response.status_code, 200)
                response.close()
            self.assertEqual(list(Path(zip_dir).iterdir()), [])

    def test_zip_is_removed_when_creation_fails(self):
        csrf = self.login()
        folder = _WORK_DIR / "broken-download"
        folder.mkdir(exist_ok=True)
        (folder / "hello.txt").write_text("hello", encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="cloudrein-zip-") as zip_dir:
            with patch("tempfile.tempdir", zip_dir), patch(
                "server.routes.files.zipfile.ZipFile",
                side_effect=OSError("zip creation detail"),
            ):
                with self.assertLogs(self.app.logger, level="ERROR"):
                    response = self.client.get(
                        "/api/file/download",
                        query_string={"path": str(folder)},
                        base_url="https://localhost",
                    )
            self.assertEqual(response.status_code, 500)
            self.assertNotIn("zip creation detail", response.get_data(as_text=True))
            self.assertEqual(list(Path(zip_dir).iterdir()), [])

    def test_batch_download_checks_resolved_path_before_permission(self):
        csrf = self.login()
        outside = _ROOT / "secret.txt"
        outside.write_text("secret", encoding="utf-8")
        raw = str(_WORK_DIR / ".." / "secret.txt")
        with patch(
            "server.routes.files.check_permission", return_value=(False, "denied")
        ) as permission:
            response = self.write(
                "/api/file/download/batch",
                csrf=csrf,
                json={"paths": [raw]},
            )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(permission.call_args[0][0], os.path.realpath(raw))

    def test_single_download_rejects_file_over_limit(self):
        self.login()
        target = _WORK_DIR / "big.bin"
        target.write_bytes(b"0123456789")
        with patch("server.routes.files.MAX_SINGLE_FILE_SIZE", 3):
            response = self.client.get(
                "/api/file/download",
                query_string={"path": str(target)},
                base_url="https://localhost",
            )
        self.assertEqual(response.status_code, 413)

    def test_directory_download_rejects_total_size_over_limit(self):
        self.login()
        folder = _WORK_DIR / "oversize-dir"
        folder.mkdir(exist_ok=True)
        (folder / "a.txt").write_bytes(b"1234")
        (folder / "b.txt").write_bytes(b"5678")
        with patch("server.routes.files.MAX_TOTAL_DOWNLOAD_SIZE", 5):
            response = self.client.get(
                "/api/file/download",
                query_string={"path": str(folder)},
                base_url="https://localhost",
            )
        self.assertEqual(response.status_code, 413)

    def test_directory_download_rejects_too_many_files(self):
        self.login()
        folder = _WORK_DIR / "many-dir"
        folder.mkdir(exist_ok=True)
        (folder / "a.txt").write_text("a", encoding="utf-8")
        (folder / "b.txt").write_text("b", encoding="utf-8")
        with patch("server.routes.files.MAX_FILES_IN_ZIP", 1):
            response = self.client.get(
                "/api/file/download",
                query_string={"path": str(folder)},
                base_url="https://localhost",
            )
        self.assertEqual(response.status_code, 400)

    def test_save_rejects_content_over_limit_before_writing(self):
        csrf = self.login()
        target = _WORK_DIR / "too-big.txt"
        target.write_text("before", encoding="utf-8")
        with patch("server.routes.files.MAX_SINGLE_FILE_SIZE", 3):
            response = self.write(
                "/api/file/save",
                csrf=csrf,
                json={"path": str(target), "content": "0123456789"},
            )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(target.read_text(encoding="utf-8"), "before")

    def test_upload_rejects_file_over_limit_and_removes_it(self):
        csrf = self.login()
        with patch("server.routes.files.MAX_SINGLE_FILE_SIZE", 3):
            response = self.write(
                "/api/file/upload",
                csrf=csrf,
                data={
                    "path": str(_WORK_DIR),
                    "file": (io.BytesIO(b"0123456789"), "too-big.bin"),
                },
                content_type="multipart/form-data",
            )
        self.assertEqual(response.status_code, 413)
        self.assertFalse((_WORK_DIR / "too-big.bin").exists())

    def test_socketio_does_not_allow_wildcard_cors(self):
        origins = self.app.extensions["socketio"].server.eio.cors_allowed_origins
        self.assertNotEqual(origins, "*")
        self.assertIsInstance(origins, list)


if __name__ == "__main__":
    unittest.main()

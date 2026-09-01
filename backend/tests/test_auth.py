import sys
import os
import unittest
import uuid
import jwt
from datetime import datetime, timedelta, timezone

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set JWT_SECRET for test environment before importing app
os.environ["JWT_SECRET"] = "test-secret-key-for-unit-tests-only-32chars"

from fastapi.testclient import TestClient
from main import app
from services.db_service import init_db, get_user_by_email
from database import users_collection
from services.auth_service import create_access_token, decode_access_token, validate_password_strength


class TestPasswordValidation(unittest.TestCase):
    """Test server-side password strength rules."""

    def test_short_password(self):
        ok, msg = validate_password_strength("Ab1!x")
        self.assertFalse(ok)
        self.assertIn("8 characters", msg)

    def test_no_uppercase(self):
        ok, msg = validate_password_strength("abcdef1!")
        self.assertFalse(ok)
        self.assertIn("uppercase", msg)

    def test_no_lowercase(self):
        ok, msg = validate_password_strength("ABCDEF1!")
        self.assertFalse(ok)
        self.assertIn("lowercase", msg)

    def test_no_digit(self):
        ok, msg = validate_password_strength("Abcdefgh!")
        self.assertFalse(ok)
        self.assertIn("digit", msg)

    def test_no_special_char(self):
        ok, msg = validate_password_strength("Abcdefg1")
        self.assertFalse(ok)
        self.assertIn("special", msg)

    def test_valid_password(self):
        ok, msg = validate_password_strength("StrongPwd1!")
        self.assertTrue(ok)


class TestAuthEndpoints(unittest.TestCase):
    """Test registration, login, and /api/auth/me endpoints."""

    def setUp(self):
        self.client = TestClient(app)
        init_db()
        self.test_email = f"testauth_{uuid.uuid4().hex}@example.com"
        self.test_password = "SecurePassword123!"
        self.test_name = "Auth Test User"

    def _register(self, email=None, password=None, full_name=None):
        return self.client.post("/api/auth/register", json={
            "email": email or self.test_email,
            "password": password or self.test_password,
            "full_name": full_name or self.test_name
        })

    def _login(self, email=None, password=None):
        return self.client.post("/api/auth/login", json={
            "email": email or self.test_email,
            "password": password or self.test_password
        })

    def test_register_valid(self):
        resp = self._register()
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["email"], self.test_email)

    def test_register_duplicate_email(self):
        self._register()
        resp = self._register()
        self.assertEqual(resp.status_code, 400)

    def test_register_invalid_email(self):
        resp = self._register(email="not-an-email")
        self.assertEqual(resp.status_code, 400)

    def test_register_weak_password_too_short(self):
        resp = self._register(password="Ab1!")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("8 characters", resp.json()["detail"])

    def test_register_weak_password_no_uppercase(self):
        resp = self._register(password="abcdefg1!")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("uppercase", resp.json()["detail"])

    def test_register_empty_name(self):
        resp = self._register(full_name="   ")
        self.assertEqual(resp.status_code, 400)

    def test_login_valid(self):
        self._register()
        resp = self._login()
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertIn("access_token", data)

    def test_login_wrong_password(self):
        self._register()
        resp = self._login(password="WrongPassword1!")
        self.assertEqual(resp.status_code, 401)

    def test_login_unknown_email(self):
        resp = self._login(email="nonexistent@example.com")
        self.assertEqual(resp.status_code, 401)

    def test_login_missing_fields(self):
        resp = self.client.post("/api/auth/login", json={
            "email": "", "password": ""
        })
        self.assertEqual(resp.status_code, 401)

    def test_me_valid_token(self):
        reg = self._register()
        token = reg.json()["access_token"]
        resp = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["user"]["email"], self.test_email)

    def test_me_missing_token(self):
        resp = self.client.get("/api/auth/me")
        self.assertEqual(resp.status_code, 401)

    def test_me_invalid_token(self):
        resp = self.client.get("/api/auth/me", headers={"Authorization": "Bearer invalid-token"})
        self.assertEqual(resp.status_code, 401)

    def test_me_expired_token(self):
        expired_token = jwt.encode(
            {"sub": "test@example.com", "exp": datetime.now(timezone.utc) - timedelta(hours=1)},
            os.environ["JWT_SECRET"],
            algorithm="HS256"
        )
        resp = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
        self.assertEqual(resp.status_code, 401)

    def test_me_malformed_bearer(self):
        resp = self.client.get("/api/auth/me", headers={"Authorization": "NotBearer abc"})
        self.assertEqual(resp.status_code, 401)


class TestScanEndpointProtection(unittest.TestCase):
    """Test that /scan requires valid JWT and enforces scan limits."""

    def setUp(self):
        self.client = TestClient(app)
        init_db()
        self.test_email = f"testscan_{uuid.uuid4().hex}@example.com"
        self.test_password = "ScanTest123!"
        self.test_name = "Scan Test User"
        reg = self.client.post("/api/auth/register", json={
            "email": self.test_email,
            "password": self.test_password,
            "full_name": self.test_name
        })
        self.token = reg.json()["access_token"]

    def _scan(self, token=None, url="https://example.com"):
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        return self.client.post("/scan", json={"url": url}, headers=headers)

    def test_scan_no_token_returns_401(self):
        resp = self.client.post("/scan", json={"url": "https://example.com"})
        # Unauthenticated scan attempts should return 401
        self.assertEqual(resp.status_code, 401)

    def test_scan_invalid_token_returns_401(self):
        resp = self._scan(token="completely-invalid-token")
        self.assertEqual(resp.status_code, 401)

    def test_scan_expired_token_returns_401(self):
        expired_token = jwt.encode(
            {"sub": self.test_email, "exp": datetime.now(timezone.utc) - timedelta(hours=1)},
            os.environ["JWT_SECRET"],
            algorithm="HS256"
        )
        resp = self._scan(token=expired_token)
        self.assertEqual(resp.status_code, 401)

    def test_scan_zero_remaining_returns_403(self):
        users_collection.update_one({"email": self.test_email}, {"$set": {"scans_remaining": 0}})

        resp = self._scan(token=self.token)
        self.assertEqual(resp.status_code, 403)
        self.assertIn("No scans remaining", resp.json()["detail"])

    def test_scan_deducts_exactly_one(self):
        users_collection.update_one({"email": self.test_email}, {"$set": {"scans_remaining": 5}})

        self._scan(token=self.token, url="https://example.com")

        user = users_collection.find_one({"email": self.test_email})
        self.assertEqual(user["scans_remaining"], 4)


class TestJWTClaims(unittest.TestCase):
    """Test that JWT tokens contain correct claims."""

    def test_token_contains_sub_iat_exp(self):
        token = create_access_token({"sub": "user@example.com"})
        payload = decode_access_token(token)
        self.assertIsNotNone(payload)
        self.assertIn("sub", payload)
        self.assertIn("iat", payload)
        self.assertIn("exp", payload)
        self.assertEqual(payload["sub"], "user@example.com")

    def test_expired_token_returns_none(self):
        expired_token = jwt.encode(
            {"sub": "user@example.com", "exp": datetime.now(timezone.utc) - timedelta(hours=1)},
            os.environ["JWT_SECRET"],
            algorithm="HS256"
        )
        payload = decode_access_token(expired_token)
        self.assertIsNone(payload)


if __name__ == "__main__":
    unittest.main(verbosity=2)

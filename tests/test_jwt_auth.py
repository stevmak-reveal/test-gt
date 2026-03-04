"""Tests for JWT authentication middleware."""

import time
import unittest

from middleware.jwt_auth import (
    JWTError,
    JWTExpiredError,
    Request,
    Response,
    create_refresh_token,
    create_token,
    decode_token,
    refresh_access_token,
    require_auth,
)

SECRET = "test-secret-key-change-in-production"


class TestCreateToken(unittest.TestCase):
    def test_creates_three_part_token(self):
        token = create_token({"sub": "user1"}, SECRET)
        parts = token.split(".")
        self.assertEqual(len(parts), 3)

    def test_payload_round_trips(self):
        payload = {"sub": "alice", "roles": ["admin"]}
        token = create_token(payload, SECRET)
        claims = decode_token(token, SECRET)
        self.assertEqual(claims["sub"], "alice")
        self.assertEqual(claims["roles"], ["admin"])

    def test_iat_and_exp_set(self):
        before = int(time.time())
        token = create_token({"sub": "u"}, SECRET, expires_in=60)
        claims = decode_token(token, SECRET)
        self.assertGreaterEqual(claims["iat"], before)
        self.assertEqual(claims["exp"], claims["iat"] + 60)


class TestDecodeToken(unittest.TestCase):
    def test_valid_token_decodes(self):
        token = create_token({"sub": "bob"}, SECRET)
        claims = decode_token(token, SECRET)
        self.assertEqual(claims["sub"], "bob")

    def test_wrong_secret_raises(self):
        token = create_token({"sub": "u"}, SECRET)
        with self.assertRaises(JWTError):
            decode_token(token, "wrong-secret")

    def test_malformed_token_raises(self):
        with self.assertRaises(JWTError):
            decode_token("not.a.valid.token.here", SECRET)

    def test_expired_token_raises_expired_error(self):
        token = create_token({"sub": "u"}, SECRET, expires_in=-1)
        with self.assertRaises(JWTExpiredError):
            decode_token(token, SECRET)

    def test_tampered_payload_raises(self):
        import base64, json as _json
        token = create_token({"sub": "user"}, SECRET)
        header, _, sig = token.split(".")
        bad_payload = base64.urlsafe_b64encode(
            _json.dumps({"sub": "admin", "iat": 0, "exp": 9999999999}).encode()
        ).rstrip(b"=").decode()
        with self.assertRaises(JWTError):
            decode_token(f"{header}.{bad_payload}.{sig}", SECRET)


class TestRefreshToken(unittest.TestCase):
    def test_refresh_token_has_type(self):
        rt = create_refresh_token({"sub": "u"}, SECRET)
        claims = decode_token(rt, SECRET)
        self.assertEqual(claims.get("token_type"), "refresh")

    def test_refresh_issues_new_access_token(self):
        rt = create_refresh_token({"sub": "carol"}, SECRET)
        new_token = refresh_access_token(rt, SECRET)
        claims = decode_token(new_token, SECRET)
        self.assertEqual(claims["sub"], "carol")
        self.assertNotIn("token_type", claims)

    def test_access_token_rejected_as_refresh(self):
        at = create_token({"sub": "u"}, SECRET)
        with self.assertRaises(JWTError):
            refresh_access_token(at, SECRET)

    def test_expired_refresh_token_raises(self):
        rt = create_refresh_token({"sub": "u"}, SECRET, expires_in=-1)
        with self.assertRaises(JWTExpiredError):
            refresh_access_token(rt, SECRET)


class TestRequireAuthDecorator(unittest.TestCase):
    def _make_request(self, token: str | None = None) -> Request:
        environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/profile"}
        if token is not None:
            environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        return Request(environ)

    def test_valid_token_passes_claims(self):
        token = create_token({"sub": "dave"}, SECRET)

        @require_auth(SECRET)
        def handler(claims, request):
            return Response({"user": claims["sub"]})

        resp = handler(self._make_request(token))
        self.assertEqual(resp.status.value, 200)
        self.assertEqual(resp.body["user"], "dave")

    def test_missing_header_returns_401(self):
        @require_auth(SECRET)
        def handler(claims, request):
            return Response({})

        resp = handler(self._make_request())
        self.assertEqual(resp.status.value, 401)

    def test_invalid_token_returns_401(self):
        @require_auth(SECRET)
        def handler(claims, request):
            return Response({})

        resp = handler(self._make_request("not-a-valid-token"))
        self.assertEqual(resp.status.value, 401)

    def test_expired_token_returns_401_with_hint(self):
        token = create_token({"sub": "u"}, SECRET, expires_in=-1)

        @require_auth(SECRET)
        def handler(claims, request):
            return Response({})

        resp = handler(self._make_request(token))
        self.assertEqual(resp.status.value, 401)
        self.assertIn("hint", resp.body)


if __name__ == "__main__":
    unittest.main()

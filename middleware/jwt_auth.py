"""JWT authentication middleware.

Validates JWT tokens on protected routes, supports token expiry and refresh.
Uses HMAC-SHA256 for signing. No external dependencies required.
"""

import base64
import hashlib
import hmac
import json
import time
from functools import wraps
from http import HTTPStatus


# ---------------------------------------------------------------------------
# JWT helpers (no third-party library)
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    # Re-add padding
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _sign(header_b64: str, payload_b64: str, secret: str) -> str:
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    return _b64url_encode(sig)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_token(payload: dict, secret: str, expires_in: int = 3600) -> str:
    """Create a signed JWT token.

    Args:
        payload: Claims to embed (sub, roles, etc.)
        secret: HMAC signing key
        expires_in: Seconds until the token expires (default 1 hour)

    Returns:
        Compact JWT string ``header.payload.signature``
    """
    now = int(time.time())
    claims = {
        **payload,
        "iat": now,
        "exp": now + expires_in,
    }
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    sig = _sign(header_b64, payload_b64, secret)
    return f"{header_b64}.{payload_b64}.{sig}"


def create_refresh_token(payload: dict, secret: str, expires_in: int = 86400 * 7) -> str:
    """Create a long-lived refresh token (default 7 days)."""
    return create_token({**payload, "token_type": "refresh"}, secret, expires_in)


def decode_token(token: str, secret: str) -> dict:
    """Decode and validate a JWT token.

    Args:
        token: Compact JWT string
        secret: HMAC signing key

    Returns:
        Decoded claims dict

    Raises:
        JWTError: If the token is invalid or expired
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise JWTError("malformed token: expected 3 parts")

        header_b64, payload_b64, sig = parts

        # Verify signature
        expected_sig = _sign(header_b64, payload_b64, secret)
        if not hmac.compare_digest(sig, expected_sig):
            raise JWTError("invalid signature")

        claims = json.loads(_b64url_decode(payload_b64))

        # Check expiry
        exp = claims.get("exp")
        if exp is not None and int(time.time()) > exp:
            raise JWTExpiredError("token has expired")

        return claims

    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        raise JWTError(f"token decode error: {exc}") from exc


def refresh_access_token(
    refresh_token: str,
    secret: str,
    access_expires_in: int = 3600,
) -> str:
    """Exchange a valid refresh token for a new access token.

    Args:
        refresh_token: Previously issued refresh token
        secret: HMAC signing key
        access_expires_in: New access token lifetime in seconds

    Returns:
        New access token

    Raises:
        JWTError: If the refresh token is invalid, expired, or not a refresh token
    """
    claims = decode_token(refresh_token, secret)
    if claims.get("token_type") != "refresh":
        raise JWTError("token is not a refresh token")

    # Strip refresh-specific fields before issuing new access token
    user_claims = {k: v for k, v in claims.items() if k not in ("iat", "exp", "token_type")}
    return create_token(user_claims, secret, expires_in=access_expires_in)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class JWTError(Exception):
    """Base class for JWT validation errors."""


class JWTExpiredError(JWTError):
    """Raised when the token has expired (allows callers to suggest refresh)."""


def require_auth(secret: str, token_header: str = "Authorization"):
    """Decorator factory that protects a route handler with JWT validation.

    Extracts the token from the ``Authorization: Bearer <token>`` header,
    validates it, and injects the decoded claims as the first argument to the
    handler.

    Usage::

        @require_auth(secret=JWT_SECRET)
        def get_profile(claims, request):
            return {"user": claims["sub"]}

    Args:
        secret: HMAC signing key used to verify tokens
        token_header: HTTP header name carrying the token (default: Authorization)

    Returns:
        Decorator that wraps route handlers
    """
    def decorator(handler):
        @wraps(handler)
        def wrapper(request, *args, **kwargs):
            auth_header = (request.headers or {}).get(token_header, "")
            if not auth_header.startswith("Bearer "):
                return _error_response(
                    HTTPStatus.UNAUTHORIZED,
                    "missing or malformed Authorization header",
                )
            token = auth_header[len("Bearer "):]
            try:
                claims = decode_token(token, secret)
            except JWTExpiredError:
                return _error_response(
                    HTTPStatus.UNAUTHORIZED,
                    "token expired",
                    hint="use the /auth/refresh endpoint to obtain a new token",
                )
            except JWTError as exc:
                return _error_response(HTTPStatus.UNAUTHORIZED, str(exc))

            return handler(claims, request, *args, **kwargs)

        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Minimal WSGI-compatible request/response helpers (framework-agnostic)
# ---------------------------------------------------------------------------

class Request:
    """Thin wrapper around a WSGI environ dict."""

    def __init__(self, environ: dict):
        self._environ = environ

    @property
    def headers(self) -> dict:
        result = {}
        for key, value in self._environ.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].replace("_", "-").title()
                result[header_name] = value
        return result

    @property
    def method(self) -> str:
        return self._environ.get("REQUEST_METHOD", "GET")

    @property
    def path(self) -> str:
        return self._environ.get("PATH_INFO", "/")


class Response:
    """Simple HTTP response."""

    def __init__(self, body: dict, status: HTTPStatus = HTTPStatus.OK):
        self.body = body
        self.status = status
        self.status_line = f"{status.value} {status.phrase}"
        self.headers = [("Content-Type", "application/json")]

    def wsgi(self):
        import json as _json
        return self.status_line, self.headers, _json.dumps(self.body).encode()


def _error_response(status: HTTPStatus, message: str, **extra) -> Response:
    body = {"error": message, **extra}
    return Response(body, status)

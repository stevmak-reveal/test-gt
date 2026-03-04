"""
Auth API: POST /auth/login and POST /auth/logout
- Login returns a signed JWT
- Logout invalidates the session via a token blacklist
"""

import datetime
import os
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

SECRET_KEY = os.environ.get("JWT_SECRET", "dev-secret-change-in-production")
TOKEN_EXPIRY_MINUTES = 60

# In-memory blacklist of invalidated JTI (JWT ID) values.
# In production this would be a Redis set or similar persistent store.
_blacklisted_jtis: set[str] = set()

# Minimal in-memory user store for demonstration purposes.
_USERS = {
    "admin": "password123",
}


def _make_token(username: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + datetime.timedelta(minutes=TOKEN_EXPIRY_MINUTES),
        "jti": os.urandom(16).hex(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def _decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])


@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    if _USERS.get(username) != password:
        return jsonify({"error": "invalid credentials"}), 401

    token = _make_token(username)
    return jsonify({"token": token}), 200


@app.post("/auth/logout")
def logout():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "missing or invalid Authorization header"}), 401

    raw_token = auth_header[len("Bearer "):]

    try:
        payload = _decode_token(raw_token)
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "token already expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid token"}), 401

    jti = payload.get("jti")
    if jti:
        _blacklisted_jtis.add(jti)

    return jsonify({"message": "logged out successfully"}), 200


if __name__ == "__main__":
    app.run(debug=False, port=5000)

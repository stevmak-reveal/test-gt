"""Tests for session management: token rotation, expiry, revocation."""

import time

import pytest

from session.store import (
    InvalidTokenError,
    RevocationError,
    SessionStore,
    TokenExpiredError,
)
from session.tokens import ACCESS_TOKEN_TTL, REFRESH_TOKEN_TTL


NOW = 1_000_000.0  # deterministic "now" for tests


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_store():
    return SessionStore()


# ---------------------------------------------------------------------------
# Session creation
# ---------------------------------------------------------------------------

class TestCreateSession:
    def test_returns_token_pair(self):
        store = make_store()
        pair = store.create_session("user1", "deviceA", now=NOW)
        assert pair.access_token
        assert pair.refresh_token
        assert pair.access_token != pair.refresh_token

    def test_access_expires_after_ttl(self):
        store = make_store()
        pair = store.create_session("user1", "deviceA", now=NOW)
        assert pair.access_expires_at == NOW + ACCESS_TOKEN_TTL

    def test_refresh_expires_after_ttl(self):
        store = make_store()
        pair = store.create_session("user1", "deviceA", now=NOW)
        assert pair.refresh_expires_at == NOW + REFRESH_TOKEN_TTL

    def test_multi_device_creates_independent_sessions(self):
        store = make_store()
        p1 = store.create_session("user1", "phone", now=NOW)
        p2 = store.create_session("user1", "laptop", now=NOW)
        assert p1.refresh_token != p2.refresh_token
        assert len(store.active_sessions("user1", now=NOW)) == 2


# ---------------------------------------------------------------------------
# Access token validation
# ---------------------------------------------------------------------------

class TestValidateAccessToken:
    def test_valid_token_returns_session(self):
        store = make_store()
        pair = store.create_session("user1", "deviceA", now=NOW)
        session = store.validate_access_token(pair.access_token, now=NOW)
        assert session.user_id == "user1"

    def test_unknown_token_raises(self):
        store = make_store()
        with pytest.raises(InvalidTokenError):
            store.validate_access_token("not-a-real-token", now=NOW)

    def test_expired_access_token_raises(self):
        store = make_store()
        pair = store.create_session("user1", "deviceA", now=NOW)
        with pytest.raises(TokenExpiredError):
            store.validate_access_token(
                pair.access_token, now=NOW + ACCESS_TOKEN_TTL + 1
            )

    def test_revoked_session_access_raises(self):
        store = make_store()
        pair = store.create_session("user1", "deviceA", now=NOW)
        store.revoke_session(pair.refresh_token)
        with pytest.raises(RevocationError):
            store.validate_access_token(pair.access_token, now=NOW)


# ---------------------------------------------------------------------------
# Refresh token rotation
# ---------------------------------------------------------------------------

class TestRotateRefreshToken:
    def test_issues_new_token_pair(self):
        store = make_store()
        pair = store.create_session("user1", "deviceA", now=NOW)
        new_pair = store.rotate_refresh_token(pair.refresh_token, now=NOW + 60)
        assert new_pair.refresh_token != pair.refresh_token
        assert new_pair.access_token != pair.access_token

    def test_old_refresh_token_invalidated(self):
        store = make_store()
        pair = store.create_session("user1", "deviceA", now=NOW)
        store.rotate_refresh_token(pair.refresh_token, now=NOW + 60)
        with pytest.raises((RevocationError, InvalidTokenError)):
            store.rotate_refresh_token(pair.refresh_token, now=NOW + 120)

    def test_old_access_token_invalidated_after_rotation(self):
        store = make_store()
        pair = store.create_session("user1", "deviceA", now=NOW)
        store.rotate_refresh_token(pair.refresh_token, now=NOW + 60)
        with pytest.raises((InvalidTokenError, RevocationError)):
            store.validate_access_token(pair.access_token, now=NOW + 120)

    def test_expired_refresh_raises(self):
        store = make_store()
        pair = store.create_session("user1", "deviceA", now=NOW)
        with pytest.raises(TokenExpiredError):
            store.rotate_refresh_token(
                pair.refresh_token, now=NOW + REFRESH_TOKEN_TTL + 1
            )

    def test_reused_revoked_token_invalidates_all_user_sessions(self):
        """Token reuse detection: revoked token reuse wipes all user sessions."""
        store = make_store()
        pair = store.create_session("user1", "phone", now=NOW)
        store.create_session("user1", "laptop", now=NOW)
        # Normal rotation
        store.rotate_refresh_token(pair.refresh_token, now=NOW + 60)
        # Attacker replays the old (now-revoked) refresh token
        with pytest.raises(RevocationError):
            store.rotate_refresh_token(pair.refresh_token, now=NOW + 120)
        # All sessions for user1 should now be gone
        assert store.active_sessions("user1", now=NOW + 120) == []

    def test_unknown_token_raises(self):
        store = make_store()
        with pytest.raises(InvalidTokenError):
            store.rotate_refresh_token("bad-token", now=NOW)


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

class TestRevocation:
    def test_revoke_single_session(self):
        store = make_store()
        p1 = store.create_session("user1", "phone", now=NOW)
        p2 = store.create_session("user1", "laptop", now=NOW)
        store.revoke_session(p1.refresh_token)
        # phone session gone, laptop still alive
        assert len(store.active_sessions("user1", now=NOW)) == 1
        remaining = store.active_sessions("user1", now=NOW)[0]
        assert remaining.device_id == "laptop"

    def test_revoke_all_user_sessions(self):
        store = make_store()
        store.create_session("user1", "phone", now=NOW)
        store.create_session("user1", "laptop", now=NOW)
        store.revoke_all_user_sessions("user1")
        assert store.active_sessions("user1", now=NOW) == []

    def test_revoke_idempotent(self):
        store = make_store()
        pair = store.create_session("user1", "deviceA", now=NOW)
        store.revoke_session(pair.refresh_token)
        store.revoke_session(pair.refresh_token)  # should not raise


# ---------------------------------------------------------------------------
# Session expiry / cleanup
# ---------------------------------------------------------------------------

class TestExpiry:
    def test_purge_removes_expired_sessions(self):
        store = make_store()
        store.create_session("user1", "phone", now=NOW)
        store.create_session("user1", "laptop", now=NOW)
        removed = store.purge_expired(now=NOW + REFRESH_TOKEN_TTL + 1)
        assert removed == 2
        assert store.active_sessions("user1", now=NOW + REFRESH_TOKEN_TTL + 1) == []

    def test_purge_leaves_valid_sessions(self):
        store = make_store()
        store.create_session("user1", "phone", now=NOW)
        store.create_session("user1", "laptop", now=NOW)
        removed = store.purge_expired(now=NOW + 60)
        assert removed == 0

    def test_active_sessions_excludes_expired(self):
        store = make_store()
        store.create_session("user1", "phone", now=NOW)
        result = store.active_sessions("user1", now=NOW + REFRESH_TOKEN_TTL + 1)
        assert result == []

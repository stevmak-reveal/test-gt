"""In-memory session store with refresh token rotation and revocation list.

For production use, replace the in-memory dicts with a persistent backend
(Redis, PostgreSQL, etc.).  The interface is intentionally backend-agnostic.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .tokens import TokenPair, issue_token_pair


@dataclass
class Session:
    user_id: str
    device_id: str
    refresh_token: str
    access_token: str
    access_expires_at: float
    refresh_expires_at: float

    def is_access_valid(self, now: float) -> bool:
        return now < self.access_expires_at

    def is_refresh_valid(self, now: float) -> bool:
        return now < self.refresh_expires_at


class RevocationError(Exception):
    """Raised when a token has been revoked."""


class TokenExpiredError(Exception):
    """Raised when a token has expired."""


class InvalidTokenError(Exception):
    """Raised when a token is unknown / was never issued."""


class SessionStore:
    """Thread-unsafe in-memory session store (add a lock for concurrent use)."""

    def __init__(self) -> None:
        # refresh_token -> Session
        self._by_refresh: Dict[str, Session] = {}
        # access_token -> Session
        self._by_access: Dict[str, Session] = {}
        # user_id -> set of refresh tokens (all active sessions for a user)
        self._user_sessions: Dict[str, Set[str]] = {}
        # revoked refresh tokens -> user_id (permanent blacklist, preserves user lookup)
        self._revoked: Dict[str, str] = {}
        # revoked access tokens (for RevocationError on stale access tokens)
        self._revoked_access: Set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_session(self, user_id: str, device_id: str,
                       now: Optional[float] = None) -> TokenPair:
        """Create a new session for a user/device and return a token pair."""
        ts = now if now is not None else time.time()
        pair = issue_token_pair(user_id, device_id, now=ts)
        session = Session(
            user_id=user_id,
            device_id=device_id,
            refresh_token=pair.refresh_token,
            access_token=pair.access_token,
            access_expires_at=pair.access_expires_at,
            refresh_expires_at=pair.refresh_expires_at,
        )
        self._store(session)
        return pair

    def validate_access_token(self, access_token: str,
                               now: Optional[float] = None) -> Session:
        """Return the session if the access token is valid, else raise."""
        ts = now if now is not None else time.time()
        if access_token in self._revoked_access:
            raise RevocationError("session has been revoked")
        session = self._by_access.get(access_token)
        if session is None:
            raise InvalidTokenError("unknown access token")
        if self._revoked_session(session):
            raise RevocationError("session has been revoked")
        if not session.is_access_valid(ts):
            raise TokenExpiredError("access token expired")
        return session

    def rotate_refresh_token(self, refresh_token: str,
                              now: Optional[float] = None) -> TokenPair:
        """Exchange a valid refresh token for a fresh token pair (rotation).

        The old refresh token is immediately revoked so it cannot be reused.
        If a previously-revoked token is presented, all sessions for that user
        are invalidated (token reuse detection).
        """
        ts = now if now is not None else time.time()

        if refresh_token in self._revoked:
            # Possible token theft — revoke all sessions for this user
            user_id = self._revoked[refresh_token]
            self._revoke_all_user_sessions(user_id)
            raise RevocationError(
                "refresh token already revoked; all user sessions invalidated"
            )

        session = self._by_refresh.get(refresh_token)
        if session is None:
            raise InvalidTokenError("unknown refresh token")
        if not session.is_refresh_valid(ts):
            self._remove_session(session)
            raise TokenExpiredError("refresh token expired")

        # Revoke old session, issue new token pair
        user_id = session.user_id
        device_id = session.device_id
        self._revoke_session(session)

        return self.create_session(user_id, device_id, now=ts)

    def revoke_session(self, refresh_token: str) -> None:
        """Explicitly revoke a single session (e.g., logout from one device)."""
        session = self._by_refresh.get(refresh_token)
        if session:
            self._revoke_session(session)
        else:
            # Idempotent — also accept already-revoked tokens
            self._revoked.setdefault(refresh_token, "")

    def revoke_all_user_sessions(self, user_id: str) -> None:
        """Revoke all sessions for a user (e.g., logout everywhere)."""
        self._revoke_all_user_sessions(user_id)

    def active_sessions(self, user_id: str,
                        now: Optional[float] = None) -> List[Session]:
        """Return all non-expired sessions for a user."""
        ts = now if now is not None else time.time()
        tokens = list(self._user_sessions.get(user_id, set()))
        result = []
        for rt in tokens:
            s = self._by_refresh.get(rt)
            if s and s.is_refresh_valid(ts):
                result.append(s)
        return result

    def purge_expired(self, now: Optional[float] = None) -> int:
        """Remove expired sessions; returns count removed."""
        ts = now if now is not None else time.time()
        expired = [
            s for s in list(self._by_refresh.values())
            if not s.is_refresh_valid(ts)
        ]
        for s in expired:
            self._remove_session(s)
        return len(expired)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _store(self, session: Session) -> None:
        self._by_refresh[session.refresh_token] = session
        self._by_access[session.access_token] = session
        self._user_sessions.setdefault(session.user_id, set()).add(
            session.refresh_token
        )

    def _revoke_session(self, session: Session) -> None:
        self._revoked[session.refresh_token] = session.user_id
        self._revoked_access.add(session.access_token)
        self._remove_session(session)

    def _remove_session(self, session: Session) -> None:
        self._by_refresh.pop(session.refresh_token, None)
        self._by_access.pop(session.access_token, None)
        self._user_sessions.get(session.user_id, set()).discard(
            session.refresh_token
        )

    def _revoked_session(self, session: Session) -> bool:
        return session.refresh_token in self._revoked

    def _revoke_all_user_sessions(self, user_id: str) -> None:
        tokens = list(self._user_sessions.get(user_id, set()))
        for rt in tokens:
            session = self._by_refresh.get(rt)
            if session:
                self._revoke_session(session)
            else:
                self._revoked.setdefault(rt, user_id)
        self._user_sessions.pop(user_id, None)

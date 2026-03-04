"""Token generation and validation utilities."""

import hashlib
import hmac
import os
import time
from dataclasses import dataclass, field
from typing import Optional


ACCESS_TOKEN_TTL = 15 * 60       # 15 minutes
REFRESH_TOKEN_TTL = 30 * 24 * 3600  # 30 days


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_at: float
    refresh_expires_at: float
    device_id: str
    user_id: str


def _generate_token() -> str:
    return hashlib.sha256(os.urandom(32)).hexdigest()


def issue_token_pair(user_id: str, device_id: str, now: Optional[float] = None) -> TokenPair:
    """Issue a new access+refresh token pair for a user/device."""
    ts = now if now is not None else time.time()
    return TokenPair(
        access_token=_generate_token(),
        refresh_token=_generate_token(),
        access_expires_at=ts + ACCESS_TOKEN_TTL,
        refresh_expires_at=ts + REFRESH_TOKEN_TTL,
        device_id=device_id,
        user_id=user_id,
    )

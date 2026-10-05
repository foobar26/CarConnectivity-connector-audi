"""Architecture-A token providers for the Audi connector.

Google Play Integrity (the ``X-Assertion`` header) gates *only* the initial
CARIAD-BFF token exchange. ``grant_type=refresh_token`` and every vehicle/command
call succeed with an ordinary bearer token off-device. So the cold-start login is
performed once on a genuine Android device (which satisfies Play Integrity) and the
resulting ``refresh_token`` is handed to this connector, which then refreshes itself
and drives all API calls without any further on-device step.

``AudiTokenProvider`` is the seam that keeps that boundary explicit:

* ``SessionTokenProvider`` — the default, drives the existing OpenID session.
* a future ``AndroidBrokerTokenProvider`` could fetch fresh tokens from a small
  on-device broker without the rest of the connector changing.

None of these ever log token material; see :func:`seed_refresh_token`.
"""

from __future__ import annotations

import abc
import hashlib
import logging
import os
from typing import TYPE_CHECKING

from carconnectivity.errors import AuthenticationError

if TYPE_CHECKING:
    from typing import Optional

    from carconnectivity_connectors.audi.auth.openid_session import OpenIDSession

LOG = logging.getLogger("carconnectivity.connectors.audi.auth")


class AudiTokenProvider(abc.ABC):
    """Supplies a valid Audi bearer access token to the connector."""

    @abc.abstractmethod
    def get_access_token(self) -> "Optional[str]":
        """Return the current access token without triggering any network I/O."""

    @abc.abstractmethod
    def ensure_valid_token(self) -> str:
        """Return a non-expired access token, refreshing or re-authenticating as needed.

        Raises:
            AuthenticationError: if no valid token can be obtained.
        """


class SessionTokenProvider(AudiTokenProvider):
    """Default provider: delegates to the connector's OpenID session.

    The session already refreshes transparently on each request, so this provider
    simply exposes that behaviour behind the :class:`AudiTokenProvider` seam and gives
    external callers a way to force a refresh ahead of a burst of requests.
    """

    def __init__(self, session: "OpenIDSession") -> None:
        self._session = session

    def get_access_token(self) -> "Optional[str]":
        return self._session.access_token

    def ensure_valid_token(self) -> str:
        session = self._session
        if not session.authorized or session.expired:
            # refresh() falls back to login() internally; let it own the strategy order.
            session.refresh()
        token = session.access_token
        if not token:
            raise AuthenticationError("No valid Audi access token available after refresh")
        return token


def seed_refresh_token(session: "OpenIDSession", refresh_token: "Optional[str]") -> bool:
    """Install an externally obtained ``refresh_token`` into `session` if it has none.

    This is the connector side of Architecture A: a ``refresh_token`` minted by the
    genuine myAudi app on-device is seeded here so the connector's normal
    ``refresh()`` can mint an access token without the Play-Integrity-gated cold-start
    exchange.

    A token already present in the session (restored from the token store, i.e. a
    previous run's possibly-still-valid token) is never overwritten — clobbering a
    working refresh token is the one unrecoverable mistake (see
    ``fix/preserve-refresh-token-on-failed-login``). To re-seed a new token, clear the
    token file first.

    Returns:
        True if the token was seeded, False if it was ignored (empty, or a token is
        already present).
    """
    if not refresh_token:
        return False
    existing = session.token
    if existing is not None and existing.get("refresh_token"):
        LOG.debug("Not seeding Audi refresh token: the session already holds one")
        return False
    # Minimal token: refresh() reads only refresh_token; the access token and expiry
    # are filled in by the first refresh. token.setter must not log this value.
    session.token = {"refresh_token": refresh_token, "token_type": "bearer"}
    LOG.info("Seeded an externally provided Audi refresh token into the session")
    return True


# Metadata key recording which token-file content was last applied, so dropping a new
# file re-provisions exactly once and a stale file left in place is ignored afterwards
# (the connector rotates its stored token on every refresh, so the file will normally
# differ from the live token — we must NOT keep overwriting the good rotated token).
_SEEDED_FILE_HASH_KEY = "seeded_refresh_file_hash"


def seed_refresh_token_from_file(session: "OpenIDSession", path: "Optional[str]") -> bool:
    """Apply a refresh token from `path`, replacing the stored one, but only when the
    file's content has changed since it was last applied.

    This is the easy re-provision path for when the refresh token is invalidated: drop
    the new token into the file and restart. Unlike :func:`seed_refresh_token`, this
    *replaces* an existing stored token — because the user supplying a new file is an
    explicit intent to re-provision — but it is gated on a hash stored in the session
    metadata so it fires once per new file and never clobbers the connector's own
    freshly rotated token on later restarts.

    Returns:
        True if a new token was applied, False otherwise (no file, empty, or unchanged).
    """
    if not path:
        return False
    try:
        with open(path, "r", encoding="utf-8") as handle:
            token = handle.read().strip()
    except OSError as err:
        LOG.warning("Could not read Audi refresh token file %s: %s", path, err)
        return False
    if not token:
        return False
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if session.metadata.get(_SEEDED_FILE_HASH_KEY) == digest:
        LOG.debug("Audi refresh token file unchanged since last applied; keeping stored token")
        return False
    session.token = {"refresh_token": token, "token_type": "bearer"}
    session.metadata[_SEEDED_FILE_HASH_KEY] = digest
    LOG.info("Applied a new Audi refresh token from %s", os.path.basename(path))
    return True

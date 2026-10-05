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
import logging
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

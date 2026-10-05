"""Tests for the Architecture-A Audi authentication seam.

Architecture A: Google Play Integrity (``X-Assertion``) gates only the cold-start token
exchange; ``grant_type=refresh_token`` and all vehicle/command calls work off-device with
a plain bearer token. So a refresh token minted on a genuine device is seeded into the
connector, which then refreshes itself. These tests cover the seam the connector relies on:
secret redaction, refresh-token seeding, the dead-cold-start classification and its cooldown,
the login/refresh lock (no auth storm), the token-provider, and tolerant callback parsing.
"""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock

import pytest

from carconnectivity.errors import AuthenticationError

from carconnectivity_connectors.audi.auth.auth_util import redact_secrets, redact_url
from carconnectivity_connectors.audi.auth.session_manager import SessionUser
from carconnectivity_connectors.audi.auth.token_provider import (
    SessionTokenProvider,
    seed_refresh_token,
)
from carconnectivity_connectors.audi.auth.we_connect_session_audi import (
    COLDSTART_UNSUPPORTED_COOLDOWN,
    StrategyNotSupportedError,
    WeConnectSession,
)


def _session() -> WeConnectSession:
    """A session with no network set up (its websession is mocked per-test)."""
    return WeConnectSession(session_user=SessionUser("user@example.com", "secret-pw"), cache={})


# --------------------------------------------------------------------------- redaction


class TestRedaction:
    def test_redact_url_masks_tokens_keeps_state(self) -> None:
        out = redact_url("myaudi:///#access_token=AAA&id_token=III&state=KEEPME&token_type=Bearer")
        assert "AAA" not in out
        assert "III" not in out
        assert "KEEPME" in out  # non-secret parameters survive for diagnostics
        assert "token_type=Bearer" in out

    def test_redact_url_tolerates_collapsed_scheme(self) -> None:
        # yarl/urlsplit may normalise myaudi:/// to myaudi:/ — still must be masked.
        out = redact_url("myaudi:/#access_token=AAA&code=CCC")
        assert "AAA" not in out and "CCC" not in out

    def test_redact_url_handles_query_form(self) -> None:
        out = redact_url("myaudi:///?code=CCC&state=S")
        assert "CCC" not in out and "state=S" in out

    def test_redact_url_empty(self) -> None:
        assert redact_url("") == ""
        assert redact_url(None) == ""

    def test_redact_secrets_masks_json_body(self) -> None:
        body = '{"access_token": "zzz", "refresh_token": "rrr", "id_token": "iii", "expires_in": 3600}'
        out = redact_secrets(body)
        for secret in ("zzz", "rrr", "iii"):
            assert secret not in out
        assert "3600" in out  # non-secret fields preserved

    def test_redact_secrets_masks_password_and_code(self) -> None:
        out = redact_secrets("password=hunter2&code=AUTHCODE&foo=bar")
        assert "hunter2" not in out and "AUTHCODE" not in out and "foo=bar" in out


# --------------------------------------------------------------------- refresh-token seed


class TestSeedRefreshToken:
    def test_seeds_when_session_empty(self) -> None:
        session = _session()
        assert session.token is None
        assert seed_refresh_token(session, "RT-from-phone") is True
        assert session.token["refresh_token"] == "RT-from-phone"

    def test_does_not_clobber_existing_refresh_token(self) -> None:
        session = _session()
        session.token = {"refresh_token": "existing", "access_token": "a", "expires_in": 3600}
        assert seed_refresh_token(session, "RT-from-phone") is False
        assert session.token["refresh_token"] == "existing"

    def test_ignores_empty(self) -> None:
        session = _session()
        assert seed_refresh_token(session, None) is False
        assert seed_refresh_token(session, "") is False
        assert session.token is None


# ---------------------------------------------------------- dead cold-start classification


class TestDeviceGrantClassification:
    def _resp(self, status: int, json_body: dict) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status
        resp.json.return_value = json_body
        resp.text = str(json_body)
        return resp

    def test_unauthorized_client_raises_strategy_not_supported(self) -> None:
        session = _session()
        session.websession = MagicMock()
        session.websession.post.return_value = self._resp(
            403, {"error": "unauthorized_client", "error_description": "client is not allowed to use the device_code grant"}
        )
        with pytest.raises(StrategyNotSupportedError):
            session._login_with_device_code()
        # cooldown armed so the next attempt fast-fails
        assert session._coldstart_unsupported_until > time.time()
        assert session._coldstart_unsupported_until <= time.time() + COLDSTART_UNSUPPORTED_COOLDOWN + 1

    def test_login_fast_fails_during_cooldown_without_network(self) -> None:
        session = _session()
        session.websession = MagicMock()
        session._coldstart_unsupported_until = time.time() + COLDSTART_UNSUPPORTED_COOLDOWN
        with pytest.raises(StrategyNotSupportedError):
            session.login()
        session.websession.post.assert_not_called()

    def test_strategy_not_supported_is_authentication_error(self) -> None:
        assert issubclass(StrategyNotSupportedError, AuthenticationError)

    def test_device_error_body_is_redacted(self) -> None:
        session = _session()
        session.websession = MagicMock()
        # A non-403 failure whose body somehow carries a token must not leak it.
        session.websession.post.return_value = self._resp(400, {"error": "x", "access_token": "LEAK"})
        with pytest.raises(AuthenticationError) as excinfo:
            session._login_with_device_code()
        assert "LEAK" not in str(excinfo.value)


# ------------------------------------------------------------------ login / refresh lock


class TestAuthLock:
    def test_concurrent_login_authenticates_once(self) -> None:
        session = _session()
        calls = {"n": 0}

        def fake_cold_start() -> None:
            calls["n"] += 1
            time.sleep(0.05)  # widen the race window
            session.token = {"access_token": "AT", "expires_in": 3600}

        session._login_with_device_code = fake_cold_start  # type: ignore[assignment]

        threads = [threading.Thread(target=session.login) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert calls["n"] == 1  # the lock + double-check collapses the storm to one login

    def test_refresh_skips_when_already_valid(self) -> None:
        session = _session()
        session.token = {"access_token": "AT", "expires_in": 3600}
        session._refresh_with_refresh_token = MagicMock(side_effect=AssertionError("should not be called"))
        session.refresh()  # already authorized and unexpired → no-op


# ----------------------------------------------------------------------- refresh fallback


class TestRefreshFallback:
    def test_refresh_without_token_falls_back_then_strategy_not_supported(self) -> None:
        session = _session()
        session._coldstart_unsupported_until = time.time() + COLDSTART_UNSUPPORTED_COOLDOWN
        # No refresh token -> _refresh_with_refresh_token raises AuthenticationError ->
        # fallback login() is attempted -> cooldown makes it StrategyNotSupportedError.
        with pytest.raises(StrategyNotSupportedError):
            session.refresh()

    def test_refresh_success_short_circuits_login(self) -> None:
        session = _session()

        def fake_refresh() -> None:
            session.token = {"access_token": "fresh", "expires_in": 3600}

        session._refresh_with_refresh_token = fake_refresh  # type: ignore[assignment]
        session.login = MagicMock(side_effect=AssertionError("login must not run after a good refresh"))
        session.refresh()
        assert session.access_token == "fresh"


# -------------------------------------------------------------------------- token provider


class TestTokenProvider:
    def test_get_access_token(self) -> None:
        session = _session()
        session.token = {"access_token": "AT", "expires_in": 3600}
        provider = SessionTokenProvider(session)
        assert provider.get_access_token() == "AT"

    def test_ensure_valid_token_refreshes_when_expired(self) -> None:
        session = _session()
        session.token = {"access_token": "old", "expires_at": time.time() - 10}

        def fake_refresh() -> None:
            session.token = {"access_token": "new", "expires_in": 3600}

        session.refresh = fake_refresh  # type: ignore[assignment]
        provider = SessionTokenProvider(session)
        assert provider.ensure_valid_token() == "new"

    def test_ensure_valid_token_raises_without_token(self) -> None:
        session = _session()
        session.refresh = MagicMock()  # refresh yields nothing
        provider = SessionTokenProvider(session)
        with pytest.raises(AuthenticationError):
            provider.ensure_valid_token()


# ------------------------------------------------------- authorization request still intact


class TestAuthorizationRequest:
    def test_authorization_url_has_pkce_state_nonce_redirect(self) -> None:
        from urllib.parse import parse_qs, urlsplit

        session = _session()
        url = session.authorization_url("https://identity.vwgroup.io/oidc/v1/authorize")
        params = parse_qs(urlsplit(url).query)
        assert params["response_type"] == ["code"]
        assert params["code_challenge_method"] == ["S256"]
        assert params["redirect_uri"] == ["myaudi:///"]
        for key in ("state", "nonce", "code_challenge", "client_id", "scope"):
            assert params.get(key) and params[key][0]


# -------------------------------------------------- tolerant myaudi:// callback parsing


class TestCallbackParsing:
    def test_parses_warm_sso_fragment_without_leaking(self, caplog) -> None:
        session = _session()
        callback = "myaudi:///#access_token=AAA&id_token=III&token_type=Bearer&expires_in=3600&state=" + session.state
        with caplog.at_level("DEBUG"):
            token = session.parse_from_fragment(callback)
        assert token["access_token"] == "AAA"
        assert token["id_token"] == "III"
        # the raw token must never appear in logs
        assert "AAA" not in caplog.text and "III" not in caplog.text

    def test_missing_access_token_does_not_crash(self) -> None:
        session = _session()
        # A code-only callback is stored as a code, not an access token.
        token = session.parse_from_fragment("myaudi:///?code=CCC&state=" + session.state)
        assert token.get("code") == "CCC"
        assert "access_token" not in token

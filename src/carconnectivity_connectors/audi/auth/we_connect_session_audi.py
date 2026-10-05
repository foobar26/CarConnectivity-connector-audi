"""
Module implements the WeConnect Session handling.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING
from urllib.parse import urljoin

import requests
from carconnectivity.errors import AuthenticationError, RetrievalError, TemporaryAuthenticationError
from oauthlib.common import to_unicode
from oauthlib.oauth2 import InsecureTransportError, is_secure_transport
from requests.models import CaseInsensitiveDict

from carconnectivity_connectors.audi.auth.audi_web_session import AudiWebSession
from carconnectivity_connectors.audi.auth.auth_util import (
    GenericFormParser,
    is_marketing_consent_url,
    marketing_consent_callback_url,
    redact_secrets,
)
from carconnectivity_connectors.audi.auth.openid_session import AccessType

# OAuth Device Authorization Grant (RFC 8628) endpoint at the VW Group identity provider.
# Since July 2026 CARIAD enforces Google Play Integrity attestation on the classic
# authorization_code token exchange (rejecting it with "invalid assertion headers"),
# which cannot be produced off-device. The device grant is not attested, so it is the
# only flow that still works for a headless client (see issue #32).
DEVICE_AUTHORIZATION_URL = "https://identity.vwgroup.io/oidc/v1/device_authorization"
# "mbb" covers the legacy MBB/fs-car endpoints; the rest cover identity and BFF vehicle data.
DEVICE_CODE_SCOPE = "openid mbb profile badge cars dealers vin"
# Overall wall-clock ceiling for the interactive-approval + polling loop (device codes
# expire after ~300s, but we cap our own effort a little below that).
DEVICE_CODE_TIMEOUT = 290

# Once the server has told us the cold-start flow is not available for this client
# (device_code grant revoked, 403 unauthorized_client — see issue, 2026-09-05), we stop
# hammering it: further cold-start attempts fast-fail for this long instead of making a
# fresh network call per expired request. A valid refresh token bypasses this entirely.
COLDSTART_UNSUPPORTED_COOLDOWN = 3600

if TYPE_CHECKING:
    pass


LOG: logging.Logger = logging.getLogger("carconnectivity.connectors.audi.auth")


class StrategyNotSupportedError(AuthenticationError):
    """The identity provider permanently refuses an OAuth flow for this client.

    Distinct from bad credentials, a transient backend failure, or an expired token:
    it means retrying the *same flow* is pointless. Today this is the revoked
    ``device_code`` grant (HTTP 403 ``unauthorized_client``). Callers treat it as
    "provide a refresh token minted on-device" rather than looping on the dead flow.
    """


class WeConnectSession(AudiWebSession):
    """
    WeConnectSession class handles the authentication and session management for Audi's WeConnect service.
    """

    def __init__(self, session_user, **kwargs) -> None:
        # Let the parent AudiWebSession handle the client_id and redirect_uri
        # Pass only the necessary parameters that don't conflict
        kwargs["session_user"] = session_user
        kwargs["cache"] = kwargs.get("cache", {})
        super(WeConnectSession, self).__init__(**kwargs)

        # Force the correct client_id after initialization.
        # The Audi native-app client (public PKCE client) accepted by the current
        # CARIAD/Auth0 token endpoint. The previous VW client (f4d0934f...) was
        # rotated out and now returns 401 invalid_client (see issues #27/#28/#29).
        self.client_id = "09b6cbec-cd19-4589-82fd-363dfa8c24da@apps_vw-dilab_com"
        self.redirect_uri = "myaudi:///"

        # Epoch after which a cold-start attempt may be retried; set when the server
        # reports the device grant is not allowed (see COLDSTART_UNSUPPORTED_COOLDOWN).
        self._coldstart_unsupported_until: float = 0.0

        LOG.debug(f"WeConnectSession initialized with client_id: {self.client_id}")
        LOG.debug(f"WeConnectSession initialized with redirect_uri: {self.redirect_uri}")

        self.headers = CaseInsensitiveDict(
            {
                "accept": "*/*",
                "content-type": "application/json",
                "content-version": "1",
                "x-newrelic-id": "VgAEWV9QDRAEXFlRAAYPUA==",
                "user-agent": "WeConnect/3 CFNetwork/1331.0.7 Darwin/21.4.0",
                "accept-language": "de-de",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            }
        )

    def request(
        self,
        method,
        url,
        data=None,
        headers=None,
        withhold_token=False,
        access_type=AccessType.ACCESS,
        token=None,
        timeout=None,
        **kwargs,
    ):
        """Intercept all requests and add weconnect-trace-id header."""

        import secrets

        traceId = secrets.token_hex(16)
        we_connect_trace_id = (
            traceId[:8] + "-" + traceId[8:12] + "-" + traceId[12:16] + "-" + traceId[16:20] + "-" + traceId[20:]
        ).upper()
        headers = headers or {}
        headers["weconnect-trace-id"] = we_connect_trace_id

        return super(WeConnectSession, self).request(
            method,
            url,
            headers=headers,
            data=data,
            withhold_token=withhold_token,
            access_type=access_type,
            token=token,
            timeout=timeout,
            **kwargs,
        )

    def login(self):
        # Cold-start note (Architecture A): since July 2026 CARIAD gates the
        # authorization_code token exchange behind Google Play Integrity, and since
        # 2026-09-05 the device_code grant is revoked for this client (403
        # unauthorized_client). Neither cold-start flow can complete off-device. The
        # supported path is to seed a refresh_token minted by the genuine myAudi app
        # (see token_provider.seed_refresh_token); login() here is the last resort and
        # is expected to raise StrategyNotSupportedError until CARIAD restores a
        # headless flow. refresh() is the hot path.
        with self._auth_lock:
            # Another thread may have authenticated us while we waited for the lock.
            if self.authorized and not self.expired:
                LOG.debug("Skipping Audi login; the session is already authenticated")
                return

            now = time.time()
            if now < self._coldstart_unsupported_until:
                raise StrategyNotSupportedError(
                    "Audi cold-start login is unavailable for this client and was already "
                    "refused recently. Provide a refresh_token obtained from the genuine "
                    "myAudi app (connector config 'refresh_token')."
                )

            LOG.info("Starting Audi device-authorization login flow")
            self._login_with_device_code()

            if not self.token or "access_token" not in self.token:
                raise AuthenticationError("Failed to obtain access token from device authorization flow")

            LOG.info("Login successful - tokens obtained via device authorization grant")

            # Set the last_login time
            self.last_login = time.time()

    def _login_with_device_code(self):
        """Run the OAuth Device Authorization Grant (RFC 8628) and auto-approve it.

        The device grant is not subject to the Play Integrity attestation CARIAD now
        enforces on the authorization_code grant, so it is the only flow that still
        completes for an off-device client. We drive the browser approval step
        programmatically using the stored username/password so no manual interaction
        is required.
        """
        # Step 1: request a device code.
        device_response = self.websession.post(
            DEVICE_AUTHORIZATION_URL,
            data={"client_id": self.client_id, "scope": DEVICE_CODE_SCOPE},
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
        if device_response.status_code != requests.codes["ok"]:
            error = None
            try:
                error = device_response.json().get("error")
            except ValueError:
                pass
            # 403 unauthorized_client / "not allowed to use the device_code grant" is a
            # deliberate, client-level revocation, not an outage or a credential problem.
            # Classify it so callers stop retrying the dead flow and start the cooldown.
            if device_response.status_code == requests.codes["forbidden"] or error == "unauthorized_client":
                self._coldstart_unsupported_until = time.time() + COLDSTART_UNSUPPORTED_COOLDOWN
                raise StrategyNotSupportedError(
                    "Audi refused the device_code grant for this client "
                    f"(HTTP {device_response.status_code}, error={error!r}). Cold-start login "
                    "is not available off-device; provide a refresh_token minted by the genuine "
                    "myAudi app (connector config 'refresh_token')."
                )
            raise AuthenticationError(
                f"Device authorization request failed: {device_response.status_code} "
                f"{redact_secrets(device_response.text)}"
            )
        device_data = device_response.json()
        if "device_code" not in device_data:
            raise AuthenticationError(f"Device authorization response missing device_code: {device_data}")

        device_code: str = device_data["device_code"]
        verification_uri: str = device_data.get("verification_uri_complete") or device_data.get("verification_uri")
        interval: int = int(device_data.get("interval", 5))
        LOG.debug(f"Device authorization started, user_code={device_data.get('user_code')}, interval={interval}s")

        # Step 2: approve the device using the stored credentials (headless).
        self._approve_device_authorization(verification_uri)

        # Step 3: poll the token endpoint until the approval is registered.
        self._poll_for_device_token(device_code, interval)

    def _approve_device_authorization(self, verification_uri: str) -> None:
        """Approve a pending device authorization using the stored username/password.

        The verification URL redirects into the normal identity.vwgroup.io sign-in
        flow (email form, then password form) and finishes on a consent page with
        "allow"/"deny" buttons, which we submit with "allow".
        """
        base = "https://identity.vwgroup.io"

        # The sign-in email form (parent follows the initial redirects for us).
        email_form = self._get_login_form(verification_uri)
        if email_form is None:
            raise AuthenticationError("Could not reach the Audi sign-in form for device approval")
        email_form.data["email"] = self.session_user.username

        # The credentials (password) form.
        password_form = self._get_password_form(urljoin(base, email_form.target), email_form.data)
        password_form.data["email"] = self.session_user.username
        password_form.data["password"] = self.session_user.password

        response = self.websession.post(
            f"{base}/signin-service/v1/{self.client_id}/{password_form.target}",
            data=password_form.data,
            allow_redirects=False,
        )

        # Follow the post-login redirect chain until we reach the device consent page
        # (a 200 HTML page carrying the allow/deny form), accepting terms if prompted
        # and skipping the optional marketing consent page.
        url = response.headers.get("Location")
        consent_page = None
        consent_url = None
        for _ in range(15):
            if not url:
                break
            full_url = urljoin(base, url)

            if "terms-and-conditions" in full_url:
                if self.accept_terms_on_login:
                    url = self._handle_consent_form(full_url)
                    continue
                raise AuthenticationError(
                    f'You need to accept the terms and conditions. Visit "{full_url}" or log into the myAudi app.'
                )

            if is_marketing_consent_url(full_url):
                url = self._skip_marketing_consent(full_url)
                continue

            response = self.websession.get(full_url, allow_redirects=False)
            if response.status_code == requests.codes["ok"]:
                consent_page = response.text
                consent_url = full_url
                break
            url = response.headers.get("Location")

        if consent_page is None or consent_url is None:
            raise AuthenticationError("Did not reach the device authorization consent page")

        # Submit the consent form with "allow" (dropping "deny" — sending both errors out).
        form = GenericFormParser()
        form.feed(consent_page)
        if form.target is None or "allow" not in form.data:
            raise AuthenticationError(
                f'Could not find the device authorization consent form at "{consent_url}". '
                "If that page asks for a consent decision, answer it once in a browser and retry."
            )
        submit_data = {key: value for key, value in form.data.items() if key != "deny"}
        if not submit_data.get("allow"):
            submit_data["allow"] = "true"

        approve_response = self.websession.post(urljoin(consent_url, form.target), data=submit_data, allow_redirects=False)
        if approve_response.status_code >= 400:
            raise AuthenticationError(
                f"Device authorization approval failed: {approve_response.status_code} {approve_response.text}"
            )
        LOG.debug("Device authorization approved")

    def _skip_marketing_consent(self, url: str) -> str:
        """Continue past the optional marketing consent page without consenting.

        The identity provider re-asks for marketing consent every few weeks, and a
        rejected prompt comes back again later. It appears as a 200 HTML page in the
        middle of the sign-in redirect chain, which would otherwise be mistaken for the
        device consent page. The page URL carries the OIDC callback that resumes the
        login granting only the scopes we originally requested, so we hand that back to
        the redirect loop and leave the marketing decision to the user's browser/app.

        We deliberately do not fetch the callback here: it answers with a redirect for
        some accounts and serves the device consent page directly for others (issue #32),
        so the loop — which already handles both — has to be the one to request it.

        Args:
            url (str): The URL of the marketing consent page.

        Returns:
            str: The next URL to follow in the redirect chain.
        """
        callback_url: str | None = marketing_consent_callback_url(url)
        if callback_url is None:
            raise AuthenticationError(
                f'Audi is asking for marketing consent and the page carries no callback to skip it: "{url}". '
                "Answer the prompt once in a browser or the myAudi app, then retry."
            )

        LOG.info("Skipping the optional marketing consent page without consenting")
        return callback_url

    def _poll_for_device_token(self, device_code: str, interval: int) -> None:
        """Poll the IDK token endpoint for the approved device_code grant."""
        token_url = "https://emea.bff.cariad.digital/auth/v1/idk/oidc/token"
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        token_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": self.client_id,
            "device_code": device_code,
        }

        deadline = time.time() + DEVICE_CODE_TIMEOUT
        while time.time() < deadline:
            response = self.websession.post(token_url, data=token_data, headers=headers)
            if response.status_code == requests.codes["ok"]:
                token_response = response.json()
                LOG.debug(f"Device token grant successful, received keys: {list(token_response.keys())}")

                new_token = {
                    "access_token": token_response["access_token"],
                    "token_type": token_response.get("token_type", "bearer"),
                }
                if "expires_in" in token_response:
                    new_token["expires_in"] = int(token_response["expires_in"])
                    new_token["expires_at"] = time.time() + int(token_response["expires_in"])
                if "id_token" in token_response:
                    new_token["id_token"] = token_response["id_token"]
                if "refresh_token" in token_response:
                    new_token["refresh_token"] = token_response["refresh_token"]
                self.token = new_token
                return

            error = None
            try:
                error = response.json().get("error")
            except ValueError:
                # Non-JSON error body (e.g. an HTML gateway error page): leave `error` as None
                # so the branch below raises AuthenticationError with the raw response text.
                pass

            if error == "authorization_pending":
                time.sleep(interval)
            elif error == "slow_down":
                interval += 5
                time.sleep(interval)
            else:
                raise AuthenticationError(f"Device token grant failed: {response.status_code} {redact_secrets(response.text)}")

        raise AuthenticationError("Timed out waiting for device authorization approval")

    def _get_audi_token(self):
        """Exchange IDK token for Audi-specific token (like ioBroker does)."""
        if not self.token or "access_token" not in self.token:
            raise AuthenticationError("No access token available for Audi token exchange")

        audi_token_url = "https://emea.bff.cariad.digital/login/v1/audi/token"

        # Use the id_token if available, otherwise use access_token
        token_to_exchange = self.token.get("id_token", self.token["access_token"])

        token_data = {
            "token": token_to_exchange,
            "grant_type": "id_token",
            "stage": "live",
            "config": "myaudi",
        }

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token['access_token']}",
        }

        LOG.debug(f"Getting Audi token at {audi_token_url}")
        try:
            response = self.websession.post(audi_token_url, json=token_data, headers=headers)
            response.raise_for_status()

            audi_response = response.json()
            LOG.debug(f"Audi token exchange successful, received keys: {list(audi_response.keys())}")

            # Update token with Audi-specific tokens
            if "access_token" in audi_response:
                self.token["audi_access_token"] = audi_response["access_token"]
            if "id_token" in audi_response:
                self.token["audi_id_token"] = audi_response["id_token"]

            LOG.info("Audi token exchange completed successfully")

        except requests.RequestException as e:
            LOG.warning(f"Audi token exchange failed (non-fatal): {e}")
            if hasattr(e, "response") and e.response is not None:
                LOG.debug(f"Audi token exchange error response: {e.response.text}")

    def refresh(self) -> None:
        # The hot path for Architecture A: a refresh_token grant is un-attested and is
        # what keeps the connector running off-device. Only if that fails do we fall back
        # to the (currently dead) cold-start login. The auth lock serialises concurrent
        # refreshes so a burst of expired-token requests triggers one refresh, not many.
        with self._auth_lock:
            # Another thread may have refreshed us while we waited for the lock.
            if self.authorized and not self.expired:
                LOG.debug("Skipping Audi refresh; the session was already refreshed")
                return
            try:
                LOG.info("Attempting token refresh using refresh_token grant")
                self._refresh_with_refresh_token()
                LOG.info("Token refresh successful")
                return
            except StrategyNotSupportedError:
                raise
            except AuthenticationError as e:
                LOG.warning("Token refresh failed: %s", e)
            except Exception as e:  # noqa: BLE001 - network/parse errors fall back to login
                LOG.warning("Token refresh failed: %s", e)

            LOG.info("Falling back to full re-authentication using login flow")
            try:
                self.login()
                LOG.info("Fallback re-authentication successful")
            except StrategyNotSupportedError as strategy_error:
                # Cold start is not available; do not loop on it. A valid refresh token
                # is the only way back, and we do not have one that works.
                LOG.error("Audi re-authentication is not possible: %s", strategy_error)
                raise
            except Exception as login_error:
                LOG.error("Fallback re-authentication also failed: %s", login_error)
                raise

    def _refresh_with_refresh_token(self):
        """Refresh tokens using the OAuth2 refresh_token grant at the IDK OIDC token endpoint."""
        if not self.token or "refresh_token" not in self.token:
            raise AuthenticationError("No refresh token available for refresh")

        token_url = "https://emea.bff.cariad.digital/auth/v1/idk/oidc/token"
        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": self.token["refresh_token"],
            "client_id": self.client_id,
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        response = self.websession.post(token_url, data=token_data, headers=headers)
        response.raise_for_status()
        token_response = response.json()

        new_token = {
            "access_token": token_response["access_token"],
            "token_type": token_response.get("token_type", "bearer"),
        }
        if "expires_in" in token_response:
            new_token["expires_in"] = int(token_response["expires_in"])
            new_token["expires_at"] = time.time() + int(token_response["expires_in"])
        if "id_token" in token_response:
            new_token["id_token"] = token_response["id_token"]
        # Keep the (possibly rotated) refresh token; reuse the old one if none returned
        new_token["refresh_token"] = token_response.get("refresh_token", self.token["refresh_token"])

        self.token = new_token

    def authorization_url(self, url, state=None, **kwargs) -> str:
        # Use the same approach as the working VW version
        # Call the parent class authorization_url method directly
        return super(WeConnectSession, self).authorization_url(url=url, state=state, **kwargs)

    def fetch_tokens(self, token_url, authorization_response=None, **_):
        """
        Fetches tokens using the given token URL using the tokens from authorization response.

        Args:
            token_url (str): The URL to request the tokens from.
            authorization_response (str, optional): The authorization response containing the tokens. Defaults to None.
            **_ : Additional keyword arguments.

        Returns:
            dict: A dictionary containing the fetched tokens if successful.
            None: If the tokens could not be fetched.

        Raises:
            TemporaryAuthenticationError: If the token request fails due to a temporary WeConnect failure.
        """
        # take token from authorization response (those are stored in self.token now!)
        self.parse_from_fragment(authorization_response)

        if self.token is not None and all(key in self.token for key in ("state", "id_token", "access_token", "code")):
            # Generate json body for token request
            body: str = json.dumps(
                {
                    "state": self.token["state"],
                    "id_token": self.token["id_token"],
                    "redirect_uri": self.redirect_uri,
                    "region": "emea",
                    "access_token": self.token["access_token"],
                    "authorizationCode": self.token["code"],
                }
            )

            request_headers: CaseInsensitiveDict = self.headers  # pyright: ignore reportAssignmentType
            request_headers["accept"] = "application/json"

            # request tokens from token_url
            token_response = self.post(
                token_url, headers=request_headers, data=body, allow_redirects=False, access_type=AccessType.ID
            )  # pyright: ignore reportCallIssue
            if token_response.status_code != requests.codes["ok"]:
                raise TemporaryAuthenticationError(
                    f"Token could not be fetched due to temporary WeConnect failure: {token_response.status_code}"
                )
            # parse token from response body
            token = self.parse_from_body(token_response.text)

            return token
        return None

    def parse_from_body(self, token_response, state=None):
        """
        Fix strange token naming before parsing it with OAuthlib.
        """
        try:
            # Tokens are in body of response in json format
            token = json.loads(token_response)
        except json.decoder.JSONDecodeError as err:
            raise TemporaryAuthenticationError(
                "Token could not be refreshed due to temporary WeConnect failure: json could not be decoded"
            ) from err
        # Fix token keys, we want access_token instead of accessToken
        if "accessToken" in token:
            token["access_token"] = token.pop("accessToken")
        # Fix token keys, we want id_token instead of idToken
        if "idToken" in token:
            token["id_token"] = token.pop("idToken")
        # Fix token keys, we want refresh_token instead of refreshToken
        if "refreshToken" in token:
            token["refresh_token"] = token.pop("refreshToken")
        # generate json from fixed dict
        fixed_token_response = to_unicode(json.dumps(token)).encode("utf-8")
        # Let OAuthlib parse the token
        return super(WeConnectSession, self).parse_from_body(token_response=fixed_token_response, state=state)

    def refresh_tokens(
        self, token_url, refresh_token=None, auth=None, timeout=None, headers=None, verify=True, proxies=None, **_
    ):
        """
        Refreshes the authentication tokens using the provided refresh token.
        Args:
            token_url (str): The URL to request new tokens from.
            refresh_token (str, optional): The refresh token to use. Defaults to None.
            auth (tuple, optional): Authentication credentials. Defaults to None.
            timeout (float or tuple, optional): How long to wait for the server to send data before giving up.
                Defaults to None.
            headers (dict, optional): Headers to include in the request. Defaults to None.
            verify (bool, optional): Whether to verify the server's TLS certificate. Defaults to True.
            proxies (dict, optional): Proxies to use for the request. Defaults to None.
            **_ (dict): Additional arguments.
        Raises:
            ValueError: If no token endpoint is set for auto_refresh.
            InsecureTransportError: If the token URL is not secure.
            AuthenticationError: If the server requests new authorization.
            TemporaryAuthenticationError: If the token could not be refreshed due to a temporary server failure.
            RetrievalError: If the status code from the server is not recognized.
        Returns:
            dict: The new tokens.
        """
        LOG.info("Refreshing tokens")
        if not token_url:
            raise ValueError("No token endpoint set for auto_refresh.")

        if not is_secure_transport(token_url):
            raise InsecureTransportError()

        # Store old refresh token in case no new one is given
        refresh_token = refresh_token or self.refresh_token

        if headers is None:
            headers = self.headers

        # Request new tokens using the refresh token
        token_response = self.get(
            token_url,
            auth=auth,
            timeout=timeout,
            headers=headers,
            verify=verify,
            withhold_token=False,  # pyright: ignore reportCallIssue
            proxies=proxies,
            access_type=AccessType.REFRESH,  # pyright: ignore reportCallIssue
        )
        if token_response.status_code == requests.codes["unauthorized"]:
            raise AuthenticationError("Refreshing tokens failed: Server requests new authorization")
        if token_response.status_code in (
            requests.codes["internal_server_error"],
            requests.codes["bad_gateway"],
            requests.codes["service_unavailable"],
            requests.codes["gateway_timeout"],
        ):
            raise TemporaryAuthenticationError(
                "Token could not be refreshed due to temporary WeConnect failure: {tokenResponse.status_code}"
            )
        if token_response.status_code == requests.codes["ok"]:
            # parse new tokens from response
            self.parse_from_body(token_response.text)
            if self.token is not None and "refresh_token" not in self.token:
                LOG.debug("No new refresh token given. Re-using old.")
                self.token["refresh_token"] = refresh_token
            return self.token
        else:
            raise RetrievalError(f"Status Code from WeConnect while refreshing tokens was: {token_response.status_code}")

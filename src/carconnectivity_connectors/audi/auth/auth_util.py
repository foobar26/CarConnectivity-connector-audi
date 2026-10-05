"""
This module provides utility functions and classes for handling authentication and parsing HTML forms
and scripts for the Audi car connectivity connector.
"""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

if TYPE_CHECKING:
    from typing import Dict, Optional


# Path fragment of the optional marketing consent page the VW Group identity provider
# periodically interjects into an otherwise successful sign-in (see issue #32).
MARKETING_CONSENT_PATH = "/consent/marketing"


# OAuth parameters that carry credentials and must never reach the logs. The myaudi://
# callback itself carries tokens in its fragment, so a stray "%s" % url or a dumped
# response body is enough to leak them (see the Architecture-A notes).
_SECRET_PARAM_NAMES = frozenset(
    {
        "access_token",
        "id_token",
        "refresh_token",
        "code",
        "authorizationcode",
        "authorization_code",
        "password",
        "code_verifier",
        "assertion",
        "x-assertion",
    }
)
# Matches "<secret-name> = <value>" or "<secret-name>: <value>" inside a JSON body or
# query/fragment string (single- or double-quoted, or bare), so we can redact token
# bodies that are not valid URLs.
_SECRET_BODY_RE = re.compile(
    r"""["']?(?P<name>""" + "|".join(sorted(_SECRET_PARAM_NAMES)) + r""")["']?\s*[:=]\s*["']?(?P<value>[^"'&\s,}]+)""",
    re.IGNORECASE,
)
_REDACTED = "<redacted>"


def redact_url(url: "Optional[str]") -> str:
    """Return `url` with the values of any credential-bearing query/fragment parameters
    replaced by a placeholder, so a callback such as ``myaudi:///#access_token=...`` can
    be logged for diagnostics without leaking the token. The scheme, host, path and the
    *names* of the parameters are preserved; only secret values are masked.
    """
    if not url:
        return ""
    try:
        split = urlsplit(url)

        def _mask(raw: str) -> str:
            if not raw:
                return raw
            parts = parse_qsl(raw, keep_blank_values=True)
            if not parts:
                return raw
            return urlencode([(k, _REDACTED if k.lower() in _SECRET_PARAM_NAMES else v) for k, v in parts])

        return urlunsplit(split._replace(query=_mask(split.query), fragment=_mask(split.fragment)))
    except ValueError:
        # Not parseable as a URL: fall back to the body redactor rather than risk a leak.
        return redact_secrets(url)


def redact_secrets(text: "Optional[str]") -> str:
    """Return `text` with the values of any credential-bearing keys masked. Works on JSON
    token bodies and arbitrary strings where :func:`redact_url` does not apply.
    """
    if not text:
        return ""
    return _SECRET_BODY_RE.sub(lambda m: f"{m.group('name')}={_REDACTED}", text)


def is_marketing_consent_url(url: str) -> bool:
    """Report whether `url` points at the VW Group marketing consent page."""
    return MARKETING_CONSENT_PATH in urlsplit(url).path


def marketing_consent_callback_url(url: str) -> Optional[str]:
    """
    Extract the OIDC callback URL embedded in a marketing consent page URL.

    The identity provider periodically interrupts the sign-in redirect chain with an
    optional marketing consent page (``.../signin-service/v1/consent/marketing/...``).
    That page URL carries the OIDC ``callback`` URL that continues the login *without*
    consenting: following it lands on ``/oidc/v1/oauth/client/callback/success`` with
    only the originally requested scopes in ``consentedScopes``, and the flow resumes.
    This keeps a headless login working instead of stalling until the user answers the
    consent prompt in a browser.

    Args:
        url (str): The URL of the marketing consent page.

    Returns:
        Optional[str]: The callback URL to follow, or None if `url` is not a marketing
                       consent page or carries no callback.
    """
    if not is_marketing_consent_url(url):
        return None

    callback: Optional[str] = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True)).get("callback")
    if not callback:
        return None

    # The callback carries space-separated scope lists, so re-encode its query to make
    # sure the URL we request is valid.
    parts = urlsplit(callback)
    return urlunsplit(parts._replace(query=urlencode(parse_qsl(parts.query, keep_blank_values=True))))


def add_bearer_auth_header(token, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Adds a Bearer token to the Authorization header.

    Args:
        token (str): The Bearer token to be added to the headers.
        headers (Optional[Dict[str, str]]): An optional dictionary of headers to which the Authorization header will be added.
                                            If not provided, a new dictionary will be created.

    Returns:
        Dict[str, str]: The headers dictionary with the added Authorization header.
    """
    headers = headers or {}
    headers["Authorization"] = f"Bearer {token}"
    return headers


class HTMLFormParser(HTMLParser):
    """
    A custom HTML parser to extract form data from HTML content.
    """

    def __init__(self, form_id) -> None:
        super().__init__()
        self._form_id = form_id
        self._inside_form: bool = False
        self.target = None
        self.data = {}

    def _get_attr(self, attrs, name):
        for attr in attrs:
            if attr[0] == name:
                return attr[1]
        return None

    def handle_starttag(self, tag, attrs) -> None:
        if self._inside_form and tag == "input":
            self.handle_input(attrs)
            return

        if tag == "form" and self._get_attr(attrs, "id") == self._form_id:
            self._inside_form = True
            self.target = self._get_attr(attrs, "action")

    def handle_endtag(self, tag) -> None:
        if tag == "form" and self._inside_form:
            self._inside_form = False

    def handle_input(self, attrs) -> None:
        if not self._inside_form:
            return

        name = self._get_attr(attrs, "name")
        value = self._get_attr(attrs, "value")

        if name:
            self.data[name] = value


class GenericFormParser(HTMLParser):
    """
    Parses the first ``<form>`` on a page, capturing its ``action`` target and every
    named ``input``/``button`` value. Used for the device-authorization consent page
    ("allow"/"deny") which carries no stable form id.
    """

    def __init__(self) -> None:
        super().__init__()
        self._inside_form: bool = False
        self.target = None
        self.data: dict = {}

    def _get_attr(self, attrs, name):
        for attr in attrs:
            if attr[0] == name:
                return attr[1]
        return None

    def handle_starttag(self, tag, attrs) -> None:
        if tag == "form" and self.target is None:
            self._inside_form = True
            self.target = self._get_attr(attrs, "action")
            return

        if self._inside_form and tag in ("input", "button"):
            name = self._get_attr(attrs, "name")
            if name:
                self.data[name] = self._get_attr(attrs, "value")

    def handle_endtag(self, tag) -> None:
        if tag == "form" and self._inside_form:
            self._inside_form = False


class ScriptFormParser(HTMLParser):
    fields: list[str] = []
    targetField: str = ""

    def __init__(self):
        super().__init__()
        self._inside_script = False
        self.data = {}
        self.target = None

    def handle_starttag(self, tag, attrs) -> None:
        if not self._inside_script and tag == "script":
            self._inside_script = True

    def handle_endtag(self, tag) -> None:
        if self._inside_script and tag == "script":
            self._inside_script = False

    def handle_data(self, data) -> None:
        if not self._inside_script:
            return

        match: re.Match[str] | None = re.search(r"templateModel: (.*?),\n", data)
        if not match:
            return

        result = json.loads(match.group(1))
        self.target = result.get(self.targetField, None)
        self.data = {k: v for k, v in result.items() if k in self.fields}

        match2 = re.search(r"csrf_token: \'(.*?)\'", data)
        if match2:
            self.data["_csrf"] = match2.group(1)


class CredentialsFormParser(ScriptFormParser):
    fields: list[str] = ["relayState", "hmac", "registerCredentialsPath", "error", "errorCode"]
    targetField: str = "postAction"


class TermsAndConditionsFormParser(ScriptFormParser):
    fields: list[str] = ["relayState", "hmac", "countryOfResidence", "legalDocuments"]
    targetField: str = "loginUrl"

    def handle_data(self, data) -> None:
        if not self._inside_script:
            return

        super().handle_data(data)

        if "countryOfResidence" in self.data:
            self.data["countryOfResidence"] = self.data["countryOfResidence"].upper()

        if "legalDocuments" not in self.data:
            return

        for key in self.data["legalDocuments"][0]:
            # Skip unnecessary keys
            if key in ("skipLink", "declineLink", "majorVersion", "minorVersion", "changeSummary"):
                continue

            # Move values under a new key while converting boolean values to 'yes' or 'no'
            v = self.data["legalDocuments"][0][key]
            self.data[f"legalDocuments[0].{key}"] = ("yes" if v else "no") if isinstance(v, bool) else v

        # Remove the original object
        del self.data["legalDocuments"]

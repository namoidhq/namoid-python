"""Hosted Auth: types, PKCE, and URL construction.

Hosted Auth redirects a user to a branded NamoID sign-in page and returns a
one-time code to the application. The Client ID resolves the application, its
environment, and its Hosted Auth domain, so there is no issuer or application
UUID to copy into configuration.

Everything in this module is pure — no I/O — so it is safe to use anywhere.
:class:`namoid.NamoIDClient` and :class:`namoid.AsyncNamoIDClient` perform the
requests.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence
from urllib.parse import urlencode, urlsplit, urlunsplit

from namoid._errors import NamoIDError

__all__ = [
    "AuthConfig",
    "HostedAuthTransaction",
    "TokenResponse",
    "TokenValidation",
    "build_configured_hosted_auth_url",
    "build_hosted_auth_url",
    "create_hosted_auth_transaction",
    "pkce_challenge",
    "random_base64url",
]

DEFAULT_API_BASE_URL = "https://api.namoid.in"

# RFC 7636 allows a 43-128 character verifier. 48 random bytes encodes to 64.
_VERIFIER_BYTES = 48
_STATE_BYTES = 32

_MODE_PATHS = {"sign_in": "/sign-in", "sign_up": "/sign-up", "waitlist": "/waitlist"}


@dataclass(frozen=True)
class AuthConfig:
    """Browser-safe configuration for an application, resolved from its Client ID."""

    client_id: str
    issuer: str
    hosted_auth_base_url: str
    hosted_auth_pages: Mapping[str, str]
    """Enabled hosted pages, keyed by ``sign_in`` / ``sign_up`` / ``waitlist`` / ``account``."""

    access_mode: str
    waitlist_enabled: bool
    signin_methods: Sequence[str]
    mfa_mode: str
    brand_logo_url: str | None = None
    brand_primary_color: str | None = None
    brand_accent_color: str | None = None
    brand_dark_mode: bool = False
    brand_locale_default: str = "en"
    support_email: str | None = None
    signup_tos_required: bool = False
    signup_tos_url: str | None = None
    signup_privacy_url: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)
    """The unmodified payload, so a newly added field is never lost."""

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> AuthConfig:
        try:
            return cls(
                client_id=payload["client_id"],
                issuer=payload["issuer"],
                hosted_auth_base_url=payload["hosted_auth_base_url"],
                hosted_auth_pages=dict(payload.get("hosted_auth_pages") or {}),
                access_mode=payload.get("access_mode", "closed"),
                waitlist_enabled=bool(payload.get("waitlist_enabled", False)),
                signin_methods=list(payload.get("signin_methods") or []),
                mfa_mode=payload.get("mfa_mode", "off"),
                brand_logo_url=payload.get("brand_logo_url"),
                brand_primary_color=payload.get("brand_primary_color"),
                brand_accent_color=payload.get("brand_accent_color"),
                brand_dark_mode=bool(payload.get("brand_dark_mode", False)),
                brand_locale_default=payload.get("brand_locale_default", "en"),
                support_email=payload.get("support_email"),
                signup_tos_required=bool(payload.get("signup_tos_required", False)),
                signup_tos_url=payload.get("signup_tos_url"),
                signup_privacy_url=payload.get("signup_privacy_url"),
                raw=dict(payload),
            )
        except KeyError as exc:
            raise NamoIDError(
                f"auth config is missing {exc.args[0]!r}", code="invalid_auth_config"
            ) from exc


@dataclass(frozen=True)
class HostedAuthTransaction:
    """State and PKCE material binding one sign-in redirect to its callback.

    Keep ``code_verifier`` server-side (or in a session) and never put it in the
    redirect. Only ``code_challenge`` travels to NamoID.
    """

    state: str
    code_verifier: str
    code_challenge: str
    code_challenge_method: str = "S256"


@dataclass(frozen=True)
class TokenResponse:
    """The NamoID session returned by a code exchange or a refresh."""

    access_token: str
    expires_in: int
    token_type: str = "Bearer"  # noqa: S105 - OAuth2 literal, not a credential
    refresh_token: str | None = None
    user_id: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> TokenResponse:
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise NamoIDError(
                "token response did not include an access_token", code="invalid_token_response"
            )
        expires_in = payload.get("expires_in")
        return cls(
            access_token=access_token,
            expires_in=int(expires_in) if isinstance(expires_in, (int, float)) else 0,
            token_type=payload.get("token_type") or "Bearer",
            refresh_token=payload.get("refresh_token"),
            user_id=str(payload["user_id"]) if payload.get("user_id") is not None else None,
            raw=dict(payload),
        )


@dataclass(frozen=True)
class TokenValidation:
    """The result of validating an access token with application credentials."""

    valid: bool
    user_id: str | None = None
    session_id: str | None = None
    client_id: str | None = None
    scopes: Sequence[str] = ()
    error: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> TokenValidation:
        return cls(
            valid=bool(payload.get("valid", False)),
            user_id=str(payload["user_id"]) if payload.get("user_id") is not None else None,
            session_id=(
                str(payload["session_id"]) if payload.get("session_id") is not None else None
            ),
            client_id=payload.get("client_id"),
            scopes=list(payload.get("scopes") or []),
            error=payload.get("error"),
            raw=dict(payload),
        )


def random_base64url(num_bytes: int = 32) -> str:
    """Cryptographically random, URL-safe, unpadded base64."""
    return _b64url(secrets.token_bytes(num_bytes))


def pkce_challenge(verifier: str) -> str:
    """The RFC 7636 S256 challenge for ``verifier``."""
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def create_hosted_auth_transaction() -> HostedAuthTransaction:
    """Create fresh ``state`` and PKCE material for one sign-in attempt."""
    verifier = random_base64url(_VERIFIER_BYTES)
    return HostedAuthTransaction(
        state=random_base64url(_STATE_BYTES),
        code_verifier=verifier,
        code_challenge=pkce_challenge(verifier),
        code_challenge_method="S256",
    )


def build_hosted_auth_url(
    base_url: str,
    *,
    return_to: str,
    state: str,
    completion_mode: str,
    mode: str = "sign_in",
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    extra_params: Mapping[str, Any] | None = None,
) -> str:
    """Build a Hosted Auth URL from a Hosted Auth domain.

    Prefer :func:`build_configured_hosted_auth_url`, which uses the exact page
    URLs the application has enabled.

    Args:
        completion_mode: ``"confidential"`` when a server will exchange the code
            with a Client Secret, ``"public"`` for a browser-only client.
    """
    path = _MODE_PATHS.get(mode)
    if path is None:
        raise NamoIDError(f"unknown Hosted Auth mode: {mode}", code="unknown_hosted_auth_mode")

    parts = urlsplit(base_url)
    if not parts.scheme or not parts.netloc:
        raise NamoIDError(
            f"hosted auth base URL must be absolute, received {base_url!r}",
            code="invalid_hosted_auth_base_url",
        )
    params = _hosted_auth_params(
        return_to=return_to,
        state=state,
        completion_mode=completion_mode,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )
    for key, value in (extra_params or {}).items():
        if value is not None:
            params[key] = _param_str(value)
    return urlunsplit((parts.scheme, parts.netloc, path, urlencode(params), ""))


def build_configured_hosted_auth_url(
    config: AuthConfig,
    *,
    return_to: str,
    state: str,
    completion_mode: str,
    mode: str = "sign_in",
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
    extra_params: Mapping[str, Any] | None = None,
) -> str:
    """Build a Hosted Auth URL from the application's own configuration.

    The configured page URL already carries the parameters that identify the
    application, so those are preserved and ``extra_params`` never overrides
    them.

    Raises:
        NamoIDError: If the requested page is not enabled for this application.
    """
    page = config.hosted_auth_pages.get(mode)
    if not page:
        raise NamoIDError(
            f"Hosted Auth page is not enabled: {mode}", code="hosted_auth_page_disabled"
        )

    parts = urlsplit(page)
    existing = _parse_query(parts.query)
    params = dict(existing)
    params.update(
        _hosted_auth_params(
            return_to=return_to,
            state=state,
            completion_mode=completion_mode,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
    )
    for key, value in (extra_params or {}).items():
        # Never let a caller overwrite what the configured page already sets.
        if value is not None and key not in params:
            params[key] = _param_str(value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), ""))


def _hosted_auth_params(
    *,
    return_to: str,
    state: str,
    completion_mode: str,
    code_challenge: str | None,
    code_challenge_method: str | None,
) -> dict:
    if completion_mode not in ("public", "confidential"):
        raise NamoIDError(
            'completion_mode must be "public" or "confidential"',
            code="invalid_completion_mode",
        )
    params = {
        "return_to": return_to,
        "state": state,
        "completion_mode": completion_mode,
    }
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = code_challenge_method or "S256"
    elif code_challenge_method:
        params["code_challenge_method"] = code_challenge_method
    return params


def _parse_query(query: str) -> dict:
    if not query:
        return {}
    from urllib.parse import parse_qsl

    return dict(parse_qsl(query, keep_blank_values=True))


def _param_str(value: Any) -> str:
    if isinstance(value, bool):
        # Match the JS SDK, which stringifies booleans as "true"/"false".
        return "true" if value else "false"
    return str(value)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

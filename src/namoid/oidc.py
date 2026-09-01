"""Standards-based OpenID Connect primitives for NamoID Customer Identity."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence
from urllib.parse import urlencode, urlsplit, urlunsplit

from namoid._errors import NamoIDError
from namoid.hosted_auth import pkce_challenge, random_base64url

__all__ = [
    "OIDCDiscovery", "OIDCTransaction", "build_authorization_url", "build_logout_url",
    "create_oidc_transaction", "validate_id_token",
]


@dataclass(frozen=True)
class OIDCDiscovery:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    revocation_endpoint: str | None = None
    end_session_endpoint: str | None = None
    code_challenge_methods_supported: Sequence[str] = ()
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any], *, expected_issuer: str) -> "OIDCDiscovery":
        issuer = _normalize_issuer(expected_issuer)
        declared = _normalize_issuer(str(payload.get("issuer") or ""))
        if declared != issuer:
            raise NamoIDError("OIDC discovery issuer mismatch", code="issuer_mismatch")
        required = ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri")
        missing = [name for name in required if not payload.get(name)]
        if missing:
            raise NamoIDError(
                f"OIDC discovery document is missing {missing[0]!r}",
                code="invalid_discovery_document",
            )
        endpoints = [payload[name] for name in required]
        endpoints += [payload.get("revocation_endpoint"), payload.get("end_session_endpoint")]
        for endpoint in filter(None, endpoints):
            _require_trusted_endpoint(issuer, str(endpoint))
        methods = list(payload.get("code_challenge_methods_supported") or [])
        if "S256" not in methods:
            raise NamoIDError("The issuer does not advertise PKCE S256", code="pkce_s256_unavailable")
        return cls(
            issuer=declared,
            authorization_endpoint=str(payload["authorization_endpoint"]),
            token_endpoint=str(payload["token_endpoint"]),
            userinfo_endpoint=str(payload["userinfo_endpoint"]),
            jwks_uri=str(payload["jwks_uri"]),
            revocation_endpoint=payload.get("revocation_endpoint"),
            end_session_endpoint=payload.get("end_session_endpoint"),
            code_challenge_methods_supported=methods,
            raw=dict(payload),
        )


@dataclass(frozen=True)
class OIDCTransaction:
    state: str
    nonce: str
    code_verifier: str
    code_challenge: str
    redirect_uri: str
    code_challenge_method: str = "S256"


def create_oidc_transaction(redirect_uri: str) -> OIDCTransaction:
    if not redirect_uri:
        raise NamoIDError("redirect_uri is required", code="missing_redirect_uri")
    verifier = random_base64url(48)
    return OIDCTransaction(
        state=random_base64url(32),
        nonce=random_base64url(32),
        code_verifier=verifier,
        code_challenge=pkce_challenge(verifier),
        redirect_uri=redirect_uri,
    )


def build_authorization_url(
    discovery: OIDCDiscovery,
    client_id: str,
    transaction: OIDCTransaction,
    *,
    scopes: Sequence[str] = ("openid", "profile", "email"),
    extra_params: Mapping[str, str] | None = None,
) -> str:
    normalized_scopes = list(dict.fromkeys(("openid", *filter(None, scopes))))
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": transaction.redirect_uri,
        "scope": " ".join(normalized_scopes),
        "state": transaction.state,
        "nonce": transaction.nonce,
        "code_challenge": transaction.code_challenge,
        "code_challenge_method": "S256",
    }
    reserved = set(params)
    for key, value in (extra_params or {}).items():
        if key not in reserved:
            params[key] = value
    parts = urlsplit(discovery.authorization_endpoint)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), ""))


def build_logout_url(
    discovery: OIDCDiscovery,
    *,
    id_token_hint: str,
    post_logout_redirect_uri: str | None = None,
    state: str | None = None,
) -> str:
    if not discovery.end_session_endpoint:
        raise NamoIDError(
            "The issuer does not advertise RP-initiated logout", code="logout_unavailable"
        )
    params = {"id_token_hint": id_token_hint}
    if post_logout_redirect_uri:
        params["post_logout_redirect_uri"] = post_logout_redirect_uri
    if state:
        params["state"] = state
    parts = urlsplit(discovery.end_session_endpoint)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), ""))


def validate_id_token(
    id_token: str,
    *,
    jwks: Mapping[str, Any],
    issuer: str,
    client_id: str,
    nonce: str,
    clock_tolerance_seconds: int = 30,
) -> Mapping[str, Any]:
    """Verify an RS256 ID token and its callback-bound nonce."""
    # Keep ordinary URL construction and public-client use lightweight. JOSE is
    # imported only when a server actually validates an ID token.
    from joserfc import jwk, jwt
    from joserfc.errors import JoseError

    try:
        keys = jwk.KeySet.import_key_set(dict(jwks))
        decoded = jwt.decode(id_token, keys, algorithms=["RS256"])
        registry = jwt.JWTClaimsRegistry(
            leeway=clock_tolerance_seconds,
            iss={"essential": True, "value": issuer.rstrip("/")},
            aud={"essential": True, "value": client_id},
            sub={"essential": True},
            iat={"essential": True},
            exp={"essential": True},
            nonce={"essential": True, "value": nonce},
        )
        registry.validate(decoded.claims)
    except (JoseError, ValueError, TypeError, KeyError) as exc:
        raise NamoIDError("ID token validation failed", code="invalid_id_token") from exc
    return dict(decoded.claims)


def _normalize_issuer(value: str) -> str:
    return value.rstrip("/")


def _require_trusted_endpoint(issuer: str, endpoint: str) -> None:
    issuer_parts = urlsplit(issuer)
    endpoint_parts = urlsplit(endpoint)
    if endpoint_parts.scheme != issuer_parts.scheme or endpoint_parts.netloc != issuer_parts.netloc:
        raise NamoIDError("OIDC endpoint is outside the configured issuer", code="untrusted_oidc_endpoint")

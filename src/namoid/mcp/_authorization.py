"""Protected-resource authorization for an MCP server, framework-agnostic.

Nothing in this module imports an MCP framework, so it can back a FastMCP
server, the official MCP Python SDK, a bare Starlette app, or a test.
:mod:`namoid.mcp.fastmcp` adapts it to FastMCP.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

import httpx
from joserfc import jwk, jws, jwt
from joserfc.errors import JoseError

# stdlib-only, so sharing the error base couples nothing.
from namoid._errors import NamoIDError

__all__ = [
    "McpCaller",
    "NamoIDMcpAuth",
    "NamoIDMcpConfigurationError",
    "NamoIDMcpTokenError",
    "create_namoid_mcp_auth",
    "create_namoid_mcp_auth_sync",
    "insufficient_scope_payload",
    "protected_resource_metadata_path",
]

# NamoID signs every environment's tokens with RS256. Nothing else is accepted.
_ALLOWED_ALGORITHMS = ["RS256"]

_DEFAULT_CLOCK_TOLERANCE_SECONDS = 30
_DEFAULT_DISCOVERY_TIMEOUT_SECONDS = 5.0

# JWKS cache lifetime. The authorization server keeps retired public keys in the
# document during rotation, so a few minutes is safe.
_DEFAULT_JWKS_TTL_SECONDS = 300.0

# Floor between JWKS refetches triggered by an unrecognised `kid`, so a stream of
# tokens carrying invented key IDs cannot be used to hammer the issuer.
_MIN_JWKS_REFRESH_INTERVAL_SECONDS = 10.0

_LOCAL_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "::1"})


class NamoIDMcpConfigurationError(NamoIDError):
    """Configuration or discovery is wrong. Raised at startup, never per request."""


class NamoIDMcpTokenError(NamoIDError):
    """A bearer token was rejected.

    The message is deliberately short and free of token contents, so it is safe
    to surface as an OAuth ``error_description``.
    """


@dataclass(frozen=True)
class McpCaller:
    """Verified identity behind a single MCP request."""

    subject: str
    """NamoID user ID (``sub``) — the human who consented, never the MCP host."""

    client_id: str
    """The OAuth client: a preregistered Client ID or a CIMD document URL."""

    scopes: frozenset
    """Scopes actually granted, not the scopes the client requested."""

    expires_at: int
    """``exp``, seconds since the epoch."""

    resource: str
    """The audience this token was minted for: this MCP server."""

    tenant_id: str | None = None
    project_id: str | None = None
    environment_id: str | None = None
    token_id: str | None = None
    """``jti``, useful for correlating your own audit records."""

    claims: Mapping[str, Any] = field(default_factory=dict)
    """All verified claims, for anything this dataclass does not surface."""

    def has_scopes(self, *scopes: str) -> bool:
        """True when every named scope was granted."""
        return all(scope in self.scopes for scope in scopes)

    def missing_scopes(self, *scopes: str) -> list[str]:
        """The named scopes that were not granted, in the order given."""
        return [scope for scope in scopes if scope not in self.scopes]


@dataclass(frozen=True)
class NamoIDMcpAuth:
    """Everything an MCP server needs to act as a NamoID protected resource."""

    issuer: str
    """The NamoID environment issuer, exactly as it spells itself."""

    resource: str
    """Canonical MCP URL, and the exact ``aud`` every accepted token carries."""

    resource_origin: str
    """Scheme and authority of :attr:`resource`."""

    mcp_path: str
    """Path component of :attr:`resource`; where the MCP endpoint belongs."""

    metadata_path: str
    """Where RFC 9728 metadata is published, derived from :attr:`resource`."""

    metadata_url: str
    """Absolute URL of that document, for ``WWW-Authenticate`` challenges."""

    protected_resource_metadata: Mapping[str, Any]
    """The RFC 9728 document to serve at :attr:`metadata_path`."""

    authorization_server: Mapping[str, Any]
    """NamoID's authorization-server metadata, fetched once at startup."""

    scopes_supported: tuple
    """Scopes advertised for an ordinary first connection."""

    _verifier: _TokenVerifier

    async def verify_access_token(self, token: str) -> McpCaller:
        """Verify a bearer token and return the caller behind it.

        Checks, in order: RS256 against the environment's JWKS, exact ``iss``,
        exact ``aud``, ``exp``/``nbf`` within the clock tolerance,
        ``token_use == "access"``, and the presence of ``sub`` and ``client_id``.

        Raises:
            NamoIDMcpTokenError: If any check fails.
        """
        return await self._verifier.verify(token)


def protected_resource_metadata_path(resource: str) -> str:
    """Derive the RFC 9728 metadata path for a resource URL.

    The well-known segment goes between the authority and the resource path, so
    ``https://mcp.acme.example/mcp`` publishes at
    ``/.well-known/oauth-protected-resource/mcp``.
    """
    path = urlsplit(resource).path
    suffix = "" if path in ("", "/") else path.rstrip("/")
    return f"/.well-known/oauth-protected-resource{suffix}"


def insufficient_scope_payload(
    auth: NamoIDMcpAuth,
    missing_scopes: Sequence[str],
    granted_scopes: Sequence[str] = (),
) -> dict:
    """Machine-readable body for a tool call that lacks a scope.

    The HTTP ``403`` + ``WWW-Authenticate`` challenge applies to the whole
    endpoint. A single tool needing an elevated scope has to answer inside the
    JSON-RPC response, so the same ``insufficient_scope`` code and
    ``resource_metadata`` pointer travel here instead — the information a host
    needs to start incremental authorization rather than give up.
    """
    scope_list = " ".join(missing_scopes)
    return {
        "error": "insufficient_scope",
        "required_scopes": list(missing_scopes),
        "granted_scopes": list(granted_scopes),
        "resource": auth.resource,
        "resource_metadata": auth.metadata_url,
        "www_authenticate": (
            f'Bearer error="insufficient_scope", scope="{scope_list}", '
            f'resource_metadata="{auth.metadata_url}"'
        ),
    }


def caller_from_claims(claims: Mapping[str, Any], *, resource: str) -> McpCaller:
    """Build an :class:`McpCaller` from claims that have already been verified.

    The single construction path, shared by token verification and by framework
    adapters that hold verified claims rather than a raw token.

    Raises:
        NamoIDMcpTokenError: If ``sub``, ``client_id``, or ``exp`` is missing.
            Without ``sub`` in particular, every caller would collapse into one
            shared identity and per-user checks would silently pass.
    """
    expires_at = claims.get("exp")
    if not isinstance(expires_at, int):
        raise NamoIDMcpTokenError("token has no expiration time")

    return McpCaller(
        subject=_required_str(claims, "sub"),
        client_id=_required_str(claims, "client_id"),
        scopes=frozenset(_parse_scopes(claims.get("scope"))),
        expires_at=expires_at,
        resource=resource,
        tenant_id=_optional_str(claims, "tid"),
        project_id=_optional_str(claims, "pid"),
        environment_id=_optional_str(claims, "eid"),
        token_id=_optional_str(claims, "jti"),
        claims=claims,
    )


def insufficient_scope_message(missing_scopes: Sequence[str]) -> str:
    """Human-readable counterpart to :func:`insufficient_scope_payload`."""
    return (
        f"This action needs additional authorization. Missing scope(s): "
        f"{' '.join(missing_scopes)}. Reconnect and approve the additional "
        f"access to continue."
    )


async def create_namoid_mcp_auth(
    *,
    issuer: str,
    resource: str,
    scopes_supported: Sequence[str],
    resource_name: str | None = None,
    resource_documentation: str | None = None,
    clock_tolerance_seconds: int = _DEFAULT_CLOCK_TOLERANCE_SECONDS,
    discovery_timeout_seconds: float = _DEFAULT_DISCOVERY_TIMEOUT_SECONDS,
    jwks_ttl_seconds: float = _DEFAULT_JWKS_TTL_SECONDS,
    jwks_min_refresh_interval_seconds: float = _MIN_JWKS_REFRESH_INTERVAL_SECONDS,
    http_client: httpx.AsyncClient | None = None,
) -> NamoIDMcpAuth:
    """Verify NamoID discovery and build a protected-resource authorizer.

    Args:
        issuer: The NamoID environment issuer, for example
            ``https://acme-test.id.namoid.in``. Test and Live differ.
        resource: The canonical public URL of this MCP server, exactly as
            registered as the resource audience in NamoID. Tokens carry this
            string in ``aud``, so any difference rejects every token.
        scopes_supported: Scopes advertised for an initial connection. Keep this
            minimal; request sensitive write scopes incrementally instead.
        resource_name: Human-readable name shown during discovery and consent.
        resource_documentation: Documentation URL to advertise.
        clock_tolerance_seconds: Allowed skew when checking ``exp``/``nbf``.
        discovery_timeout_seconds: Timeout for the startup discovery fetch.
        http_client: Reused for discovery and JWKS instead of a per-fetch client.

    Raises:
        NamoIDMcpConfigurationError: If the issuer or resource URL is unusable,
            the issuer is unreachable, or its metadata declares a different
            issuer. Raised at startup so a misconfiguration is not an opaque
            401 on the first tool call.
    """
    plan = _plan(
        issuer=issuer,
        resource=resource,
        scopes_supported=scopes_supported,
        resource_name=resource_name,
        resource_documentation=resource_documentation,
    )

    url = _discovery_url(plan.issuer)
    if http_client is not None:
        raw = await _get_json_async(http_client, url, discovery_timeout_seconds)
        document = _parse_discovery(plan.issuer, url, raw)
    else:
        async with httpx.AsyncClient() as client:
            raw = await _get_json_async(client, url, discovery_timeout_seconds)
            document = _parse_discovery(plan.issuer, url, raw)

    return _assemble(
        plan,
        document,
        clock_tolerance_seconds,
        http_client,
        jwks_ttl_seconds=jwks_ttl_seconds,
        jwks_min_refresh_interval_seconds=jwks_min_refresh_interval_seconds,
    )


def create_namoid_mcp_auth_sync(
    *,
    issuer: str,
    resource: str,
    scopes_supported: Sequence[str],
    resource_name: str | None = None,
    resource_documentation: str | None = None,
    clock_tolerance_seconds: int = _DEFAULT_CLOCK_TOLERANCE_SECONDS,
    discovery_timeout_seconds: float = _DEFAULT_DISCOVERY_TIMEOUT_SECONDS,
    jwks_ttl_seconds: float = _DEFAULT_JWKS_TTL_SECONDS,
    jwks_min_refresh_interval_seconds: float = _MIN_JWKS_REFRESH_INTERVAL_SECONDS,
) -> NamoIDMcpAuth:
    """Blocking form of :func:`create_namoid_mcp_auth`.

    MCP servers are usually constructed at module import, where there is no
    running event loop to await discovery on. Token verification stays async.
    """
    plan = _plan(
        issuer=issuer,
        resource=resource,
        scopes_supported=scopes_supported,
        resource_name=resource_name,
        resource_documentation=resource_documentation,
    )

    url = _discovery_url(plan.issuer)
    try:
        response = httpx.get(
            url,
            headers={"accept": "application/json"},
            timeout=discovery_timeout_seconds,
            follow_redirects=False,
        )
        response.raise_for_status()
        payload = response.json()
    except httpx.HTTPError as exc:
        raise NamoIDMcpConfigurationError(f"could not reach {url}: {exc}") from exc
    except ValueError as exc:
        raise NamoIDMcpConfigurationError(f"{url} did not return JSON") from exc

    return _assemble(
        plan,
        _parse_discovery(plan.issuer, url, payload),
        clock_tolerance_seconds,
        None,
        jwks_ttl_seconds=jwks_ttl_seconds,
        jwks_min_refresh_interval_seconds=jwks_min_refresh_interval_seconds,
    )


# ─── internals ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Plan:
    issuer: str
    resource: str
    resource_origin: str
    mcp_path: str
    metadata_path: str
    metadata_url: str
    scopes_supported: tuple
    resource_name: str | None
    resource_documentation: str | None


def _plan(
    *,
    issuer: str,
    resource: str,
    scopes_supported: Sequence[str],
    resource_name: str | None,
    resource_documentation: str | None,
) -> _Plan:
    checked_issuer = _validate_issuer(issuer)
    parts = _validate_resource(resource)
    resource_url = urlunsplit(parts)
    origin = f"{parts.scheme}://{parts.netloc}"
    mcp_path = parts.path or "/"
    metadata_path = protected_resource_metadata_path(resource_url)
    return _Plan(
        issuer=checked_issuer,
        resource=resource_url,
        resource_origin=origin,
        mcp_path=mcp_path,
        metadata_path=metadata_path,
        metadata_url=f"{origin}{metadata_path}",
        scopes_supported=tuple(scopes_supported),
        resource_name=resource_name,
        resource_documentation=resource_documentation,
    )


def _assemble(
    plan: _Plan,
    document: Mapping[str, Any],
    clock_tolerance_seconds: int,
    http_client: httpx.AsyncClient | None,
    *,
    jwks_ttl_seconds: float = _DEFAULT_JWKS_TTL_SECONDS,
    jwks_min_refresh_interval_seconds: float = _MIN_JWKS_REFRESH_INTERVAL_SECONDS,
) -> NamoIDMcpAuth:
    metadata: dict = {
        "resource": plan.resource,
        # `document["issuer"]` is the issuer's own spelling of itself.
        # Publishing that exact string keeps RFC 8414's exact-match issuer
        # comparison working for a client that follows this document back to
        # the authorization server. A normalized or slash-appended copy breaks
        # strict clients.
        "authorization_servers": [document["issuer"]],
        "scopes_supported": list(plan.scopes_supported),
        "bearer_methods_supported": ["header"],
    }
    if plan.resource_name is not None:
        metadata["resource_name"] = plan.resource_name
    if plan.resource_documentation is not None:
        metadata["resource_documentation"] = plan.resource_documentation

    verifier = _TokenVerifier(
        jwks=_JwksCache(
            str(document["jwks_uri"]),
            http_client=http_client,
            ttl_seconds=jwks_ttl_seconds,
            min_refresh_interval_seconds=jwks_min_refresh_interval_seconds,
        ),
        issuer=plan.issuer,
        resource=plan.resource,
        clock_tolerance_seconds=clock_tolerance_seconds,
    )

    return NamoIDMcpAuth(
        issuer=plan.issuer,
        resource=plan.resource,
        resource_origin=plan.resource_origin,
        mcp_path=plan.mcp_path,
        metadata_path=plan.metadata_path,
        metadata_url=plan.metadata_url,
        protected_resource_metadata=metadata,
        authorization_server=document,
        scopes_supported=plan.scopes_supported,
        _verifier=verifier,
    )


def _discovery_url(issuer: str) -> str:
    return f"{issuer}/.well-known/oauth-authorization-server"


async def _get_json_async(client: httpx.AsyncClient, url: str, timeout: float) -> Any:
    try:
        response = await client.get(
            url,
            headers={"accept": "application/json"},
            timeout=timeout,
            follow_redirects=False,
        )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as exc:
        raise NamoIDMcpConfigurationError(f"could not reach {url}: {exc}") from exc
    except ValueError as exc:
        raise NamoIDMcpConfigurationError(f"{url} did not return JSON") from exc


def _parse_discovery(issuer: str, url: str, payload: Any) -> Mapping[str, Any]:
    if not isinstance(payload, dict):
        raise NamoIDMcpConfigurationError(f"{url} did not return an OAuth metadata document")

    declared = payload.get("issuer")
    if not isinstance(declared, str) or not declared:
        raise NamoIDMcpConfigurationError(f"{url} does not declare an issuer")

    # RFC 9700 mix-up defence: the document must claim the issuer we asked for.
    if declared != issuer:
        raise NamoIDMcpConfigurationError(
            f"issuer mismatch: expected {issuer} but {url} declares {declared}"
        )

    jwks_uri = payload.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        raise NamoIDMcpConfigurationError(f"{url} does not advertise a jwks_uri")

    return payload


class _JwksCache:
    """Caches the environment's JWKS, refetching when a ``kid`` is unknown.

    The authorization server signs with one active key and keeps retired public
    keys published during rotation, so a token may legitimately carry a ``kid``
    that is newer than the cached document.
    """

    def __init__(
        self,
        uri: str,
        *,
        http_client: httpx.AsyncClient | None = None,
        ttl_seconds: float = _DEFAULT_JWKS_TTL_SECONDS,
        min_refresh_interval_seconds: float = _MIN_JWKS_REFRESH_INTERVAL_SECONDS,
    ) -> None:
        self._uri = uri
        self._http_client = http_client
        self._ttl = ttl_seconds
        self._min_refresh_interval = min_refresh_interval_seconds
        self._key_set: jwk.KeySet | None = None
        self._kids: frozenset = frozenset()
        self._fetched_at = 0.0
        self._lock = asyncio.Lock()

    async def key_set(self, *, kid: str | None) -> jwk.KeySet:
        async with self._lock:
            now = time.monotonic()
            fresh = self._key_set is not None and (now - self._fetched_at) < self._ttl
            known_kid = kid is None or kid in self._kids
            if fresh and known_kid:
                return self._key_set  # type: ignore[return-value]

            # An unknown kid justifies an early refetch, but only at a bounded
            # rate so invented key IDs cannot be turned into traffic.
            if self._key_set is not None and (now - self._fetched_at) < self._min_refresh_interval:
                return self._key_set

            document = await self._fetch()
            try:
                key_set = jwk.KeySet.import_key_set(document)
            except (JoseError, ValueError, TypeError, KeyError) as exc:
                raise NamoIDMcpTokenError("the signing keys could not be read") from exc

            self._key_set = key_set
            self._kids = frozenset(
                str(entry["kid"])
                for entry in document.get("keys", [])
                if isinstance(entry, dict) and entry.get("kid")
            )
            self._fetched_at = now
            return key_set

    async def _fetch(self) -> dict:
        try:
            if self._http_client is not None:
                response = await self._http_client.get(
                    self._uri, headers={"accept": "application/json"}
                )
            else:
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        self._uri, headers={"accept": "application/json"}
                    )
            response.raise_for_status()
            document = response.json()
        except httpx.HTTPError as exc:
            raise NamoIDMcpTokenError("the signing keys are unavailable") from exc
        except ValueError as exc:
            raise NamoIDMcpTokenError("the signing keys could not be read") from exc
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise NamoIDMcpTokenError("the signing keys could not be read")
        return document


class _TokenVerifier:
    def __init__(
        self,
        *,
        jwks: _JwksCache,
        issuer: str,
        resource: str,
        clock_tolerance_seconds: int,
    ) -> None:
        self._jwks = jwks
        self._issuer = issuer
        self._resource = resource
        self._claims = jwt.JWTClaimsRegistry(
            leeway=clock_tolerance_seconds,
            iss={"essential": True, "value": issuer},
            aud={"essential": True, "value": resource},
            sub={"essential": True},
            exp={"essential": True},
        )

    async def verify(self, token: str) -> McpCaller:
        kid = _unverified_kid(token)
        key_set = await self._jwks.key_set(kid=kid)

        try:
            decoded = jwt.decode(token, key_set, algorithms=_ALLOWED_ALGORITHMS)
        except JoseError as exc:
            raise NamoIDMcpTokenError(_describe(exc)) from exc
        except (ValueError, TypeError) as exc:
            raise NamoIDMcpTokenError("token could not be verified") from exc

        try:
            self._claims.validate(decoded.claims)
        except JoseError as exc:
            raise NamoIDMcpTokenError(_describe(exc)) from exc

        claims = decoded.claims

        # An ID token is not an API token. NamoID stamps `token_use` so a
        # resource server can tell them apart even though both are RS256 JWTs
        # from the same issuer carrying the same `iss`.
        if claims.get("token_use") != "access":
            raise NamoIDMcpTokenError("token is not an access token")

        return caller_from_claims(claims, resource=self._resource)


def _unverified_kid(token: str) -> str | None:
    """Read ``kid`` from the JOSE header without trusting anything in it.

    Used only to decide whether the cached JWKS is stale; verification still
    resolves the signing key through the key set. A failure here is not fatal,
    it just means the cache cannot be pre-warmed for this token.
    """
    try:
        header = jws.extract_compact(token.encode()).headers()
    except (JoseError, ValueError, TypeError, UnicodeEncodeError):
        return None
    kid = header.get("kid")
    return kid if isinstance(kid, str) and kid else None


_MISMATCH = "token issuer or audience does not match this MCP server"


def _describe(error: JoseError) -> str:
    """Map a verification failure to a short, non-revealing reason.

    Never include the token, a claim value, or a stack trace: this string is
    returned to the caller as an OAuth ``error_description``.
    """
    name = type(error).__name__
    text = str(error).lower()

    if name == "ExpiredTokenError" or "expired" in text:
        return "token has expired"
    if name in ("MissingKeyError", "InvalidKeyIdError"):
        return "token was signed with an unknown key"
    if name in ("UnsupportedAlgorithmError", "MissingAlgorithmError", "ConflictAlgorithmError"):
        return "token uses an unsupported signing algorithm"
    if name in ("BadSignatureError", "InvalidSignatureError"):
        return "token signature could not be verified"
    if name == "MissingClaimError":
        # Distinct from a mismatch: saying "audience does not match" for an
        # absent `sub` would send an integrator down the wrong path.
        return "token is missing a required claim"
    if name == "InvalidClaimError":
        # A wrong `iss` or a wrong `aud`.
        return _MISMATCH
    if "audience" in text or "issuer" in text:
        return _MISMATCH
    return "token could not be verified"


def _parse_scopes(scope: Any) -> list[str]:
    if not isinstance(scope, str):
        return []
    return [item for item in scope.split() if item]


def _required_str(claims: Mapping[str, Any], claim: str) -> str:
    value = claims.get(claim)
    if not isinstance(value, str) or not value:
        raise NamoIDMcpTokenError(f"token is missing the {claim} claim")
    return value


def _optional_str(claims: Mapping[str, Any], claim: str) -> str | None:
    value = claims.get(claim)
    return value if isinstance(value, str) and value else None


def _validate_issuer(value: str) -> str:
    issuer = value.strip().rstrip("/")
    parts = urlsplit(issuer)
    if not parts.scheme or not parts.netloc:
        raise NamoIDMcpConfigurationError(
            f"issuer must be an absolute URL, received {value!r}"
        )
    if parts.query or parts.fragment:
        raise NamoIDMcpConfigurationError(
            "issuer must not contain a query string or fragment"
        )
    if parts.scheme != "https" and not _is_local_hostname(parts.hostname):
        raise NamoIDMcpConfigurationError("issuer must use https outside local development")
    return issuer


def _validate_resource(value: str):
    parts = urlsplit(value.strip())
    if not parts.scheme or not parts.netloc:
        raise NamoIDMcpConfigurationError(
            f"resource must be an absolute URL, received {value!r}"
        )
    if parts.fragment:
        # RFC 8707 resource indicators carry no fragment, and `aud` is compared
        # as an exact string.
        raise NamoIDMcpConfigurationError("resource must not contain a fragment")
    if parts.scheme != "https" and not _is_local_hostname(parts.hostname):
        raise NamoIDMcpConfigurationError("resource must use https outside local development")
    return parts


def _is_local_hostname(hostname: str | None) -> bool:
    if hostname is None:
        return False
    return hostname in _LOCAL_HOSTNAMES or hostname.endswith(".localhost")

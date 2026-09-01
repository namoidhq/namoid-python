"""FastMCP adapter for NamoID protected-resource authorization.

Requires the ``fastmcp`` extra::

    pip install "namoid[fastmcp]"

Typical use, at module scope where there is no event loop to await on::

    from fastmcp import FastMCP
    from namoid.mcp.fastmcp import create_namoid_auth, require_namoid_scopes

    auth = create_namoid_auth(
        issuer="https://acme-test.id.namoid.in",
        resource="https://mcp.acme.example/mcp",
        scopes_supported=["customers:read", "invoices:read"],
        resource_name="Acme Finance MCP",
    )

    mcp = FastMCP(name="acme-finance-mcp", auth=auth.provider)

    @mcp.tool
    @require_namoid_scopes(auth, "refunds:create")
    def issue_refund(invoice_id: str, amount_minor: int) -> dict:
        caller = current_caller(auth)
        ...

    mcp.run(transport="http", path=auth.mcp_path)
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Any, Callable, Sequence, TypeVar

from fastmcp.server.auth import AccessToken, RemoteAuthProvider, TokenVerifier
from fastmcp.server.dependencies import get_access_token
from fastmcp.tools.tool import ToolResult
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from namoid.mcp._authorization import (
    McpCaller,
    NamoIDMcpAuth,
    NamoIDMcpTokenError,
    caller_from_claims,
    create_namoid_mcp_auth_sync,
    insufficient_scope_message,
    insufficient_scope_payload,
)

__all__ = [
    "NamoIDAuthProvider",
    "NamoIDFastMCPAuth",
    "NamoIDTokenVerifier",
    "create_namoid_auth",
    "current_caller",
    "require_namoid_scopes",
]

F = TypeVar("F", bound=Callable[..., Any])


class NamoIDTokenVerifier(TokenVerifier):
    """Adapts NamoID token verification to FastMCP's ``TokenVerifier``.

    This wraps :class:`~namoid.mcp.NamoIDMcpAuth` rather than subclassing
    FastMCP's ``JWTVerifier``, which matters for two reasons.

    ``JWTVerifier`` has no opinion on ``token_use``, so an ID token for the same
    audience would be accepted as an MCP API token. It also leaves
    ``AccessToken.subject`` unset, which would make every caller look like the
    same anonymous principal — per-user authorization in tool handlers would
    then all apply to one shared identity. Both are enforced by the core
    verifier, so neither can be lost by a change in FastMCP's internals.
    """

    def __init__(self, authorization: NamoIDMcpAuth, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._authorization = authorization

    @property
    def scopes_supported(self) -> list[str]:
        return list(self._authorization.scopes_supported)

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            caller = await self._authorization.verify_access_token(token)
        except NamoIDMcpTokenError:
            # FastMCP turns None into a 401 plus the WWW-Authenticate challenge
            # that starts client discovery. The reason stays server-side.
            return None
        return AccessToken(
            token=token,
            client_id=caller.client_id,
            scopes=sorted(caller.scopes),
            expires_at=caller.expires_at,
            subject=caller.subject,
            claims=dict(caller.claims),
        )


class NamoIDAuthProvider(RemoteAuthProvider):
    """Publishes NamoID's protected-resource metadata verbatim.

    ``RemoteAuthProvider`` stores authorization servers as pydantic
    ``AnyHttpUrl``, which appends a trailing slash to a bare-authority URL:
    ``https://acme-test.id.namoid.in`` serializes as
    ``https://acme-test.id.namoid.in/``. NamoID's discovery document declares
    the issuer without that slash, and RFC 8414 compares issuer identifiers
    exactly, so a strict client that follows the advertised authorization server
    and compares the returned ``issuer`` would see a mismatch. A client building
    the well-known URL by concatenation would also produce a double slash.

    Token verification and the ``WWW-Authenticate`` challenge are inherited
    unchanged; only the served document is replaced.
    """

    def __init__(self, authorization: NamoIDMcpAuth, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._authorization = authorization

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        # Preserve the lifecycle hook the base class documents, then publish our
        # own document instead of a re-serialized copy.
        self.set_mcp_path(mcp_path)

        metadata = dict(self._authorization.protected_resource_metadata)

        async def protected_resource_metadata(_request: Request) -> JSONResponse:
            return JSONResponse(
                metadata,
                headers={
                    "Cache-Control": "public, max-age=300",
                    # Browser-based MCP clients fetch discovery cross-origin.
                    # Only this document is world-readable.
                    "Access-Control-Allow-Origin": "*",
                },
            )

        return [
            Route(
                self._authorization.metadata_path,
                protected_resource_metadata,
                methods=["GET", "OPTIONS"],
            )
        ]


@dataclass(frozen=True)
class NamoIDFastMCPAuth:
    """A ready-to-mount FastMCP auth provider plus the values needed to serve it."""

    provider: NamoIDAuthProvider
    """Pass to ``FastMCP(auth=...)``."""

    authorization: NamoIDMcpAuth
    """The framework-agnostic core, for direct token verification or tests."""

    @property
    def issuer(self) -> str:
        return self.authorization.issuer

    @property
    def resource(self) -> str:
        return self.authorization.resource

    @property
    def mcp_path(self) -> str:
        """Pass to ``mcp.run(path=...)`` so the endpoint matches the audience."""
        return self.authorization.mcp_path

    @property
    def metadata_path(self) -> str:
        return self.authorization.metadata_path

    @property
    def metadata_url(self) -> str:
        return self.authorization.metadata_url

    @property
    def scopes_supported(self) -> tuple:
        return self.authorization.scopes_supported


def create_namoid_auth(
    *,
    issuer: str,
    resource: str,
    scopes_supported: Sequence[str],
    resource_name: str | None = None,
    resource_documentation: str | None = None,
    clock_tolerance_seconds: int = 30,
    discovery_timeout_seconds: float = 5.0,
) -> NamoIDFastMCPAuth:
    """Run NamoID discovery and build a FastMCP auth provider.

    Blocking, because FastMCP servers are built at module import where there is
    no running event loop. Token verification is async.

    Raises:
        NamoIDMcpConfigurationError: If the issuer or resource URL is unusable,
            the issuer is unreachable, or its metadata declares a different
            issuer — at startup, rather than as an opaque 401 later.
    """
    authorization = create_namoid_mcp_auth_sync(
        issuer=issuer,
        resource=resource,
        scopes_supported=scopes_supported,
        resource_name=resource_name,
        resource_documentation=resource_documentation,
        clock_tolerance_seconds=clock_tolerance_seconds,
        discovery_timeout_seconds=discovery_timeout_seconds,
    )

    verifier = NamoIDTokenVerifier(
        authorization,
        # Connecting needs a valid token, not every scope. Individual tools
        # enforce their own, so a read-only client can still connect.
        required_scopes=None,
    )
    provider = NamoIDAuthProvider(
        authorization,
        token_verifier=verifier,
        authorization_servers=[AnyHttpUrl(authorization.issuer)],
        base_url=authorization.resource_origin,
        scopes_supported=list(authorization.scopes_supported),
        resource_name=resource_name,
    )
    return NamoIDFastMCPAuth(provider=provider, authorization=authorization)


def current_caller(auth: NamoIDFastMCPAuth | NamoIDMcpAuth) -> McpCaller:
    """The verified caller behind the current tool invocation.

    Returns the NamoID user who consented — never the MCP host or the client
    application.
    """
    # Both wrapper and core expose `resource`; the audience is the same either way.
    token = get_access_token()
    return caller_from_claims(dict(token.claims or {}), resource=auth.resource)


def require_namoid_scopes(
    auth: NamoIDFastMCPAuth | NamoIDMcpAuth, *scopes: str
) -> Callable[[F], F]:
    """Run a tool only when the caller's token carries every required scope.

    Prefer this over FastMCP's built-in ``require_scopes`` for MCP
    authorization. The built-in *filters* the tool out of ``tools/list`` for
    callers who lack the scope, so the host never learns the tool exists and
    cannot ask the user to approve it. Incremental authorization needs the
    opposite: the tool stays visible, and an attempted call answers with an
    ``insufficient_scope`` challenge naming exactly what is missing.

    Use the built-in when hiding a capability is the goal. Use this when the
    user should be able to grant it.

    A scope is permission to *attempt* an action. Ownership, organization
    boundaries, and transaction limits still belong in the tool body.
    """
    core = auth.authorization if isinstance(auth, NamoIDFastMCPAuth) else auth

    def decorate(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            granted = set(get_access_token().scopes)
            missing = [scope for scope in scopes if scope not in granted]
            if missing:
                return ToolResult(
                    content=insufficient_scope_message(missing),
                    structured_content=insufficient_scope_payload(
                        core, missing, sorted(granted)
                    ),
                    is_error=True,
                )
            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorate

"""namoid: Python SDK for NamoID, enterprise identity for India (OAuth 2.1 / OIDC).

Two independent surfaces. Take either, both, or neither — nothing is loaded
until you name it.

**Hosted Auth** — redirect users to a branded NamoID sign-in page and exchange
the returned code for a session. :class:`NamoIDClient` and
:class:`AsyncNamoIDClient` here; pure helpers in :mod:`namoid.hosted_auth`.
Needs only the base install.

**MCP authorization** — protect an MCP server so NamoID issues short-lived,
audience-bound tokens for it. In :mod:`namoid.mcp` (extra: ``mcp``) with a
FastMCP adapter in :mod:`namoid.mcp.fastmcp` (extra: ``fastmcp``).

The two never import each other. Importing this package does not import either
one: the names below resolve on first use (PEP 562), so an MCP-only server never
loads the Hosted Auth client, and a Hosted Auth app never loads the MCP code or
needs its extra installed.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

__version__ = "0.2.0"
__homepage__ = "https://namoid.in"

# Public name -> the module that defines it. Resolved on first attribute access
# so importing `namoid` stays free of httpx client construction and of any
# optional dependency.
_LAZY_EXPORTS = {
    "AsyncNamoIDClient": "namoid._client",
    "NamoIDClient": "namoid._client",
    "NamoIDError": "namoid._errors",
    "AuthConfig": "namoid.hosted_auth",
    "HostedAuthTransaction": "namoid.hosted_auth",
    "TokenResponse": "namoid.hosted_auth",
    "TokenValidation": "namoid.hosted_auth",
    "OIDCDiscovery": "namoid.oidc",
    "OIDCTransaction": "namoid.oidc",
    "build_authorization_url": "namoid.oidc",
    "build_logout_url": "namoid.oidc",
    "create_oidc_transaction": "namoid.oidc",
    "validate_id_token": "namoid.oidc",
    "build_configured_hosted_auth_url": "namoid.hosted_auth",
    "build_hosted_auth_url": "namoid.hosted_auth",
    "create_hosted_auth_transaction": "namoid.hosted_auth",
}

__all__ = [
    "AsyncNamoIDClient",
    "AuthConfig",
    "HostedAuthTransaction",
    "NamoIDClient",
    "NamoIDError",
    "OIDCDiscovery",
    "OIDCTransaction",
    "TokenResponse",
    "TokenValidation",
    "__homepage__",
    "__version__",
    "build_configured_hosted_auth_url",
    "build_hosted_auth_url",
    "build_authorization_url",
    "build_logout_url",
    "create_oidc_transaction",
    "validate_id_token",
    "create_hosted_auth_transaction",
]


def __getattr__(name: str) -> Any:
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    # Cache on the module so later lookups skip this path entirely.
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_EXPORTS))


if TYPE_CHECKING:
    # Import eagerly for type checkers and IDEs, which do not run __getattr__.
    from namoid._client import AsyncNamoIDClient as AsyncNamoIDClient
    from namoid._client import NamoIDClient as NamoIDClient
    from namoid._errors import NamoIDError as NamoIDError
    from namoid.hosted_auth import AuthConfig as AuthConfig
    from namoid.hosted_auth import HostedAuthTransaction as HostedAuthTransaction
    from namoid.hosted_auth import TokenResponse as TokenResponse
    from namoid.hosted_auth import TokenValidation as TokenValidation
    from namoid.hosted_auth import (
        build_configured_hosted_auth_url as build_configured_hosted_auth_url,
    )
    from namoid.oidc import OIDCDiscovery as OIDCDiscovery
    from namoid.oidc import OIDCTransaction as OIDCTransaction
    from namoid.oidc import build_authorization_url as build_authorization_url
    from namoid.oidc import build_logout_url as build_logout_url
    from namoid.oidc import create_oidc_transaction as create_oidc_transaction
    from namoid.oidc import validate_id_token as validate_id_token
    from namoid.hosted_auth import build_hosted_auth_url as build_hosted_auth_url
    from namoid.hosted_auth import (
        create_hosted_auth_transaction as create_hosted_auth_transaction,
    )

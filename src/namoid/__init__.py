"""namoid: Python SDK for NamoID, enterprise identity for India (OAuth 2.1 / OIDC).

Hosted Auth lives here: :class:`NamoIDClient` and :class:`AsyncNamoIDClient`,
with pure helpers in :mod:`namoid.hosted_auth`. MCP authorization is in
:mod:`namoid.mcp`, behind the ``mcp`` or ``fastmcp`` extra.
"""

from __future__ import annotations

from namoid._client import AsyncNamoIDClient, NamoIDClient
from namoid._errors import NamoIDError
from namoid.hosted_auth import (
    AuthConfig,
    HostedAuthTransaction,
    TokenResponse,
    TokenValidation,
    build_configured_hosted_auth_url,
    build_hosted_auth_url,
    create_hosted_auth_transaction,
)

__version__ = "0.1.0"
__homepage__ = "https://namoid.in"

__all__ = [
    "AsyncNamoIDClient",
    "AuthConfig",
    "HostedAuthTransaction",
    "NamoIDClient",
    "NamoIDError",
    "TokenResponse",
    "TokenValidation",
    "__homepage__",
    "__version__",
    "build_configured_hosted_auth_url",
    "build_hosted_auth_url",
    "create_hosted_auth_transaction",
]

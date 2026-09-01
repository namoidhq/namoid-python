"""Protect an MCP server with NamoID.

NamoID is the authorization server. Your MCP server is the protected resource.
An MCP host — Claude, ChatGPT, Cursor, VS Code — is the OAuth client, and the
signed-in human is the resource owner. NamoID authenticates that human, records
consent, and issues a short-lived token limited to your server and to the
actions approved; this package validates and enforces it.

No NamoID credentials are needed: a resource server only consumes public
discovery metadata and JWKS.

Nothing here imports an MCP framework. For FastMCP, use
:mod:`namoid.mcp.fastmcp`, which is available with the ``fastmcp`` extra.
"""

from __future__ import annotations

from namoid._errors import NamoIDError
from namoid.mcp._authorization import (
    McpCaller,
    NamoIDMcpAuth,
    NamoIDMcpConfigurationError,
    NamoIDMcpTokenError,
    caller_from_claims,
    create_namoid_mcp_auth,
    create_namoid_mcp_auth_sync,
    insufficient_scope_message,
    insufficient_scope_payload,
    protected_resource_metadata_path,
)

__all__ = [
    "McpCaller",
    "NamoIDError",
    "NamoIDMcpAuth",
    "NamoIDMcpConfigurationError",
    "NamoIDMcpTokenError",
    "caller_from_claims",
    "create_namoid_mcp_auth",
    "create_namoid_mcp_auth_sync",
    "insufficient_scope_message",
    "insufficient_scope_payload",
    "protected_resource_metadata_path",
]

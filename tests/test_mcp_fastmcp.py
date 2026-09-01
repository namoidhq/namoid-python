"""The FastMCP adapter: token verifier, metadata route, and scope guard."""

from __future__ import annotations

import json

import pytest

fastmcp_adapter = pytest.importorskip(
    "namoid.mcp.fastmcp", reason="requires the fastmcp extra"
)

create_namoid_auth = fastmcp_adapter.create_namoid_auth
require_namoid_scopes = fastmcp_adapter.require_namoid_scopes

RESOURCE = "https://mcp.acme.example/mcp"


def build(server, **overrides):
    options = {
        "issuer": server.issuer,
        "resource": RESOURCE,
        "scopes_supported": ["customers:read", "invoices:read"],
        "resource_name": "Acme Finance MCP",
    }
    options.update(overrides)
    return create_namoid_auth(**options)


class FakeAccessToken:
    """Stands in for what FastMCP injects into a tool invocation."""

    def __init__(self, scopes, claims=None):
        self.scopes = scopes
        self.claims = claims or {}
        self.token = "opaque"
        self.client_id = "client"


def test_exposes_the_values_needed_to_mount_the_server(authorization_server):
    auth = build(authorization_server)

    assert auth.issuer == authorization_server.issuer
    assert auth.resource == RESOURCE
    assert auth.mcp_path == "/mcp"
    assert auth.metadata_path == "/.well-known/oauth-protected-resource/mcp"
    assert auth.metadata_url == f"https://mcp.acme.example{auth.metadata_path}"
    assert auth.scopes_supported == ("customers:read", "invoices:read")
    assert auth.provider.token_verifier.scopes_supported == [
        "customers:read",
        "invoices:read",
    ]


async def test_verifier_populates_subject(authorization_server):
    """FastMCP's own JWTVerifier leaves `subject` unset, collapsing all callers
    into one anonymous identity. This adapter must not."""
    auth = build(authorization_server)
    token = authorization_server.mint(
        audience=RESOURCE, scope="customers:read invoices:read", subject="user-42"
    )

    access = await auth.provider.verify_token(token)

    assert access is not None
    assert access.subject == "user-42"
    assert access.client_id == "https://client.example/oauth/metadata.json"
    assert access.scopes == ["customers:read", "invoices:read"]
    assert access.claims["tid"] == "tenant-uuid"


@pytest.mark.parametrize(
    ("label", "mint_kwargs"),
    [
        ("another MCP server's audience", {"audience": "https://other.example/mcp"}),
        ("an ID token", {"audience": RESOURCE, "token_use": "id"}),
        ("a different issuer", {"audience": RESOURCE, "issuer": "https://evil.example"}),
        ("no subject", {"audience": RESOURCE, "subject": None}),
        ("an expired token", {"audience": RESOURCE, "expires_in": -60}),
    ],
)
async def test_verifier_returns_none_for_rejected_tokens(
    authorization_server, label, mint_kwargs
):
    """FastMCP turns None into a 401 plus the discovery challenge."""
    auth = build(authorization_server)
    token = authorization_server.mint(**mint_kwargs)
    assert await auth.provider.verify_token(token) is None, label


async def test_verifier_returns_none_for_a_malformed_token(authorization_server):
    auth = build(authorization_server)
    assert await auth.provider.verify_token("not-a-jwt") is None


async def test_publishes_metadata_with_the_exact_issuer(authorization_server):
    auth = build(authorization_server)

    routes = auth.provider.get_routes(mcp_path="/mcp")
    metadata_routes = [r for r in routes if r.path == auth.metadata_path]
    assert len(metadata_routes) == 1, f"expected one metadata route, got {routes}"

    response = await metadata_routes[0].endpoint(None)
    document = json.loads(bytes(response.body))

    # pydantic's AnyHttpUrl would render this as "<issuer>/", breaking RFC 8414
    # exact issuer comparison for a client that follows it back to the AS.
    assert document["authorization_servers"] == [authorization_server.issuer]
    assert not document["authorization_servers"][0].endswith("/")
    assert document["resource"] == RESOURCE
    assert document["scopes_supported"] == ["customers:read", "invoices:read"]
    assert document["bearer_methods_supported"] == ["header"]
    assert response.headers["cache-control"] == "public, max-age=300"


def test_require_scopes_runs_the_handler_when_granted(authorization_server, monkeypatch):
    auth = build(authorization_server)
    monkeypatch.setattr(
        fastmcp_adapter,
        "get_access_token",
        lambda: FakeAccessToken(["invoices:read", "refunds:create"]),
    )

    @require_namoid_scopes(auth, "refunds:create")
    def issue_refund(invoice_id: str) -> dict:
        return {"refunded": invoice_id}

    assert issue_refund(invoice_id="inv_1") == {"refunded": "inv_1"}


def test_require_scopes_challenges_a_missing_scope(authorization_server, monkeypatch):
    auth = build(authorization_server)
    monkeypatch.setattr(
        fastmcp_adapter,
        "get_access_token",
        lambda: FakeAccessToken(["invoices:read"]),
    )

    ran = False

    @require_namoid_scopes(auth, "refunds:create")
    def issue_refund(invoice_id: str) -> dict:
        nonlocal ran
        ran = True
        return {}

    result = issue_refund(invoice_id="inv_1")

    assert ran is False, "the handler must not run without its scope"
    assert result.is_error is True
    payload = result.structured_content
    assert payload["error"] == "insufficient_scope"
    assert payload["required_scopes"] == ["refunds:create"]
    assert payload["granted_scopes"] == ["invoices:read"]
    assert payload["resource_metadata"] == auth.metadata_url
    assert 'scope="refunds:create"' in payload["www_authenticate"]


def test_require_scopes_preserves_the_tool_signature(authorization_server, monkeypatch):
    """FastMCP builds a tool schema from the wrapped function's signature."""
    import inspect

    auth = build(authorization_server)
    monkeypatch.setattr(
        fastmcp_adapter, "get_access_token", lambda: FakeAccessToken([])
    )

    @require_namoid_scopes(auth, "invoices:read")
    def list_invoices(status: str = "open") -> dict:
        """List invoices."""
        return {}

    assert list_invoices.__name__ == "list_invoices"
    assert list_invoices.__doc__ == "List invoices."
    assert list(inspect.signature(list_invoices).parameters) == ["status"]


def test_current_caller_reconstructs_the_verified_identity(
    authorization_server, monkeypatch
):
    auth = build(authorization_server)
    monkeypatch.setattr(
        fastmcp_adapter,
        "get_access_token",
        lambda: FakeAccessToken(
            ["invoices:read"],
            claims={
                "sub": "user-77",
                "client_id": "https://client.example/metadata.json",
                "scope": "invoices:read",
                "exp": 2_000_000_000,
                "tid": "tenant-uuid",
                "eid": "environment-uuid",
            },
        ),
    )

    caller = fastmcp_adapter.current_caller(auth)

    assert caller.subject == "user-77"
    assert caller.resource == RESOURCE
    assert caller.tenant_id == "tenant-uuid"
    assert caller.environment_id == "environment-uuid"
    assert caller.has_scopes("invoices:read")

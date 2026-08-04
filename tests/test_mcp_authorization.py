"""Core protected-resource authorization: discovery, verification, metadata."""

from __future__ import annotations

import pytest

from namoid.mcp import (
    NamoIDMcpConfigurationError,
    NamoIDMcpTokenError,
    create_namoid_mcp_auth,
    create_namoid_mcp_auth_sync,
    insufficient_scope_payload,
    protected_resource_metadata_path,
)

RESOURCE = "https://mcp.acme.example/mcp"


def build(server, **overrides):
    options = {
        "issuer": server.issuer,
        "resource": RESOURCE,
        "scopes_supported": ["customers:read", "invoices:read"],
        "resource_name": "Acme Finance MCP",
    }
    options.update(overrides)
    return create_namoid_mcp_auth_sync(**options)


def test_derives_the_rfc_9728_metadata_path():
    assert (
        protected_resource_metadata_path("https://mcp.acme.example/mcp")
        == "/.well-known/oauth-protected-resource/mcp"
    )
    assert (
        protected_resource_metadata_path("https://mcp.acme.example/")
        == "/.well-known/oauth-protected-resource"
    )
    assert (
        protected_resource_metadata_path("https://mcp.acme.example/a/b/")
        == "/.well-known/oauth-protected-resource/a/b"
    )


def test_publishes_the_issuer_exactly_as_the_issuer_spells_it(authorization_server):
    auth = build(authorization_server)
    metadata = auth.protected_resource_metadata

    # A trailing slash here would break RFC 8414's exact issuer comparison for
    # any client that follows this document back to the authorization server.
    assert metadata["authorization_servers"] == [authorization_server.issuer]
    assert metadata["resource"] == RESOURCE
    assert metadata["resource_name"] == "Acme Finance MCP"
    assert metadata["bearer_methods_supported"] == ["header"]
    assert auth.metadata_path == "/.well-known/oauth-protected-resource/mcp"
    assert auth.metadata_url == f"https://mcp.acme.example{auth.metadata_path}"
    assert auth.mcp_path == "/mcp"


def test_rejects_discovery_that_declares_a_different_issuer(authorization_server):
    authorization_server.declared_issuer = "https://someone-else.example"
    with pytest.raises(NamoIDMcpConfigurationError, match="issuer mismatch"):
        build(authorization_server)


def test_rejects_discovery_without_a_jwks_uri(authorization_server):
    authorization_server.omit_jwks_uri = True
    with pytest.raises(NamoIDMcpConfigurationError, match="jwks_uri"):
        build(authorization_server)


def test_rejects_an_unreachable_issuer():
    # Port 1 on loopback refuses connections, so this never leaves the machine.
    with pytest.raises(NamoIDMcpConfigurationError, match="could not reach"):
        create_namoid_mcp_auth_sync(
            issuer="http://127.0.0.1:1",
            resource=RESOURCE,
            scopes_supported=[],
        )


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"issuer": "not-a-url", "resource": RESOURCE}, "absolute URL"),
        ({"issuer": "http://acme.example", "resource": RESOURCE}, "https"),
        ({"issuer": "https://a.example?x=1", "resource": RESOURCE}, "query"),
        ({"issuer": "https://a.example", "resource": f"{RESOURCE}#frag"}, "fragment"),
        ({"issuer": "https://a.example", "resource": "http://mcp.acme.example/mcp"}, "https"),
        ({"issuer": "https://a.example", "resource": "/relative"}, "absolute URL"),
    ],
)
def test_rejects_unusable_configuration_before_any_network_call(options, message):
    with pytest.raises(NamoIDMcpConfigurationError, match=message):
        create_namoid_mcp_auth_sync(scopes_supported=[], **options)


async def test_accepts_an_audience_bound_access_token(authorization_server):
    auth = build(authorization_server)
    token = authorization_server.mint(
        audience=RESOURCE, scope="customers:read invoices:read"
    )

    caller = await auth.verify_access_token(token)

    assert caller.subject == "user-uuid-1"
    assert caller.client_id == "https://client.example/oauth/metadata.json"
    assert caller.scopes == frozenset({"customers:read", "invoices:read"})
    assert caller.resource == RESOURCE
    assert caller.tenant_id == "tenant-uuid"
    assert caller.project_id == "project-uuid"
    assert caller.environment_id == "environment-uuid"
    assert caller.token_id == "token-uuid"
    assert caller.has_scopes("customers:read")
    assert caller.missing_scopes("refunds:create") == ["refunds:create"]


@pytest.mark.parametrize(
    ("label", "mint_kwargs", "message"),
    [
        (
            "a token minted for another MCP server",
            {"audience": "https://other.example/mcp"},
            "issuer or audience",
        ),
        (
            "an ID token presented as an API token",
            {"audience": RESOURCE, "token_use": "id"},
            "not an access token",
        ),
        (
            "a token with no token_use at all",
            {"audience": RESOURCE, "token_use": None},
            "not an access token",
        ),
        (
            "a token from a different issuer",
            {"audience": RESOURCE, "issuer": "https://evil.example"},
            "issuer or audience",
        ),
        (
            "a token with no subject",
            {"audience": RESOURCE, "subject": None},
            "missing a required claim",
        ),
        (
            "a token with no client_id",
            {"audience": RESOURCE, "client_id": None},
            "missing the client_id claim",
        ),
        (
            "an expired token",
            {"audience": RESOURCE, "expires_in": -60},
            "expired",
        ),
    ],
)
async def test_rejects_tokens_that_must_never_reach_a_tool(
    authorization_server, label, mint_kwargs, message
):
    auth = build(authorization_server)
    token = authorization_server.mint(**mint_kwargs)
    with pytest.raises(NamoIDMcpTokenError, match=message):
        await auth.verify_access_token(token)


async def test_rejects_a_malformed_token(authorization_server):
    auth = build(authorization_server)
    with pytest.raises(NamoIDMcpTokenError):
        await auth.verify_access_token("not-a-jwt-at-all")


async def test_rejects_a_signature_from_a_key_outside_the_jwks(authorization_server):
    """Every claim is right; only the signing key is wrong."""
    auth = build(authorization_server)

    # Mint with a key the server knows, then drop it from the published JWKS so
    # verification has to fail on the signature rather than on a claim.
    authorization_server.add_key("rogue-key")
    token = authorization_server.mint(audience=RESOURCE, kid="rogue-key")
    del authorization_server.keys["rogue-key"]

    with pytest.raises(NamoIDMcpTokenError):
        await auth.verify_access_token(token)


async def test_caches_jwks_and_refetches_when_a_kid_is_unknown(authorization_server):
    auth = build(authorization_server, jwks_min_refresh_interval_seconds=0)

    first = authorization_server.mint(audience=RESOURCE, scope="invoices:read")
    await auth.verify_access_token(first)
    after_first = authorization_server.jwks_request_count
    assert after_first == 1, "the first verification should fetch the key set"

    # A second token signed with the same key must reuse the cache.
    await auth.verify_access_token(authorization_server.mint(audience=RESOURCE))
    assert authorization_server.jwks_request_count == after_first, "JWKS should be cached"

    # Key rotation: a token signed with a newly published kid forces a refetch
    # and then verifies, because the issuer keeps retired keys during rotation.
    authorization_server.add_key("test-key-2")
    rotated = authorization_server.mint(audience=RESOURCE, kid="test-key-2")
    caller = await auth.verify_access_token(rotated)
    assert caller.subject == "user-uuid-1"
    assert authorization_server.jwks_request_count == after_first + 1


async def test_unknown_kid_refetches_are_rate_limited(authorization_server):
    """Invented key IDs must not be usable to hammer the issuer's JWKS."""
    auth = build(authorization_server, jwks_min_refresh_interval_seconds=3600)

    await auth.verify_access_token(authorization_server.mint(audience=RESOURCE))
    baseline = authorization_server.jwks_request_count

    # A brand-new key is published, but the cooldown has not elapsed, so the
    # cached key set is used and the token fails instead of triggering a fetch.
    authorization_server.add_key("test-key-3")
    with pytest.raises(NamoIDMcpTokenError):
        await auth.verify_access_token(
            authorization_server.mint(audience=RESOURCE, kid="test-key-3")
        )
    assert authorization_server.jwks_request_count == baseline


async def test_async_factory_matches_the_sync_one(authorization_server):
    auth = await create_namoid_mcp_auth(
        issuer=authorization_server.issuer,
        resource=RESOURCE,
        scopes_supported=["invoices:read"],
    )
    assert auth.protected_resource_metadata["authorization_servers"] == [
        authorization_server.issuer
    ]
    caller = await auth.verify_access_token(
        authorization_server.mint(audience=RESOURCE, scope="invoices:read")
    )
    assert caller.scopes == frozenset({"invoices:read"})


def test_insufficient_scope_payload_carries_what_a_host_needs(authorization_server):
    auth = build(authorization_server)
    payload = insufficient_scope_payload(auth, ["refunds:create"], ["invoices:read"])

    assert payload["error"] == "insufficient_scope"
    assert payload["required_scopes"] == ["refunds:create"]
    assert payload["granted_scopes"] == ["invoices:read"]
    assert payload["resource"] == RESOURCE
    assert payload["resource_metadata"] == auth.metadata_url
    assert 'error="insufficient_scope"' in payload["www_authenticate"]
    assert 'scope="refunds:create"' in payload["www_authenticate"]
    assert auth.metadata_url in payload["www_authenticate"]

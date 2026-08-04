"""Hosted Auth: PKCE, URL construction, and both client flavours."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from namoid import (
    AsyncNamoIDClient,
    AuthConfig,
    NamoIDClient,
    NamoIDError,
    create_hosted_auth_transaction,
)
from namoid.hosted_auth import (
    build_configured_hosted_auth_url,
    build_hosted_auth_url,
    pkce_challenge,
    random_base64url,
)

CLIENT_ID = "namoid_client_test_abcdefghijklmnop"
CLIENT_SECRET = "namoid_secret_test_abcdefghijklmnop"  # noqa: S105 - test fixture

CONFIG_PAYLOAD = {
    "client_id": CLIENT_ID,
    "issuer": "https://acme-test.id.namoid.in",
    "hosted_auth_base_url": "https://acme-test.id.namoid.in",
    "hosted_auth_pages": {
        "sign_in": f"https://acme-test.id.namoid.in/sign-in?client_id={CLIENT_ID}",
        "sign_up": f"https://acme-test.id.namoid.in/sign-up?client_id={CLIENT_ID}",
    },
    "access_mode": "open",
    "waitlist_enabled": False,
    "signin_methods": ["email_otp", "passkey"],
    "mfa_mode": "optional",
    "brand_logo_url": None,
    "brand_primary_color": "#0b6650",
    "brand_accent_color": None,
    "brand_dark_mode": False,
    "brand_locale_default": "en",
    "support_email": "help@acme.example",
    "signup_tos_required": True,
    "signup_tos_url": "https://acme.example/terms",
    "signup_privacy_url": "https://acme.example/privacy",
}

TOKEN_PAYLOAD = {
    "access_token": "access-token-value",
    "refresh_token": "refresh-token-value",
    "token_type": "Bearer",
    "expires_in": 900,
    "user_id": "11111111-1111-1111-1111-111111111111",
}


def recorder(handler):
    """Collect the requests a client makes, alongside a response handler."""
    seen: list[httpx.Request] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    return seen, httpx.MockTransport(transport_handler)


def sync_client(handler, **kwargs):
    seen, transport = recorder(handler)
    return seen, NamoIDClient(
        client_id=CLIENT_ID, http_client=httpx.Client(transport=transport), **kwargs
    )


def async_client(handler, **kwargs):
    seen, transport = recorder(handler)
    return seen, AsyncNamoIDClient(
        client_id=CLIENT_ID, http_client=httpx.AsyncClient(transport=transport), **kwargs
    )


# ─── pure helpers ───────────────────────────────────────────────────────────


def test_transaction_carries_rfc_7636_material():
    transaction = create_hosted_auth_transaction()

    assert transaction.code_challenge_method == "S256"
    assert 43 <= len(transaction.code_verifier) <= 128
    assert transaction.state != transaction.code_verifier
    # The challenge must be the SHA-256 of the verifier, base64url without padding.
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(transaction.code_verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    assert transaction.code_challenge == expected
    assert "=" not in transaction.code_challenge


def test_transactions_are_unique():
    states = {create_hosted_auth_transaction().state for _ in range(50)}
    assert len(states) == 50


def test_random_and_challenge_are_url_safe():
    for _ in range(20):
        value = random_base64url(48)
        assert "=" not in value and "+" not in value and "/" not in value
    assert pkce_challenge("a" * 43) == pkce_challenge("a" * 43)
    assert pkce_challenge("a" * 43) != pkce_challenge("b" * 43)


def test_builds_a_hosted_auth_url_from_a_domain():
    url = build_hosted_auth_url(
        "https://acme-test.id.namoid.in",
        return_to="https://app.example/callback",
        state="state-value",
        completion_mode="confidential",
        code_challenge="challenge-value",
    )
    parts = urlsplit(url)
    query = parse_qs(parts.query)

    assert parts.path == "/sign-in"
    assert query["return_to"] == ["https://app.example/callback"]
    assert query["state"] == ["state-value"]
    assert query["completion_mode"] == ["confidential"]
    assert query["code_challenge"] == ["challenge-value"]
    assert query["code_challenge_method"] == ["S256"]


@pytest.mark.parametrize(
    ("mode", "path"),
    [("sign_in", "/sign-in"), ("sign_up", "/sign-up"), ("waitlist", "/waitlist")],
)
def test_hosted_auth_url_modes(mode, path):
    url = build_hosted_auth_url(
        "https://acme-test.id.namoid.in",
        mode=mode,
        return_to="https://app.example/callback",
        state="s",
        completion_mode="public",
    )
    assert urlsplit(url).path == path


def test_rejects_an_unknown_mode_and_a_bad_completion_mode():
    with pytest.raises(NamoIDError, match="unknown Hosted Auth mode"):
        build_hosted_auth_url(
            "https://acme-test.id.namoid.in",
            mode="nope",
            return_to="https://app.example/cb",
            state="s",
            completion_mode="public",
        )
    with pytest.raises(NamoIDError, match="completion_mode"):
        build_hosted_auth_url(
            "https://acme-test.id.namoid.in",
            return_to="https://app.example/cb",
            state="s",
            completion_mode="sometimes",
        )


def test_configured_url_preserves_the_application_parameters():
    config = AuthConfig.from_payload(CONFIG_PAYLOAD)
    url = build_configured_hosted_auth_url(
        config,
        return_to="https://app.example/callback",
        state="state-value",
        completion_mode="public",
        code_challenge="challenge-value",
        extra_params={"login_hint": "user@example.com", "client_id": "attacker"},
    )
    query = parse_qs(urlsplit(url).query)

    # The client_id already on the configured page must survive untouched.
    assert query["client_id"] == [CLIENT_ID]
    assert query["login_hint"] == ["user@example.com"]
    assert query["state"] == ["state-value"]


def test_configured_url_refuses_a_disabled_page():
    config = AuthConfig.from_payload(CONFIG_PAYLOAD)
    with pytest.raises(NamoIDError, match="not enabled: waitlist"):
        build_configured_hosted_auth_url(
            config,
            mode="waitlist",
            return_to="https://app.example/cb",
            state="s",
            completion_mode="public",
        )


def test_auth_config_keeps_unknown_fields_and_reports_missing_ones():
    config = AuthConfig.from_payload({**CONFIG_PAYLOAD, "future_flag": True})
    assert config.support_email == "help@acme.example"
    assert config.raw["future_flag"] is True

    with pytest.raises(NamoIDError, match="missing 'issuer'"):
        AuthConfig.from_payload({"client_id": CLIENT_ID})


# ─── client behaviour ───────────────────────────────────────────────────────


def test_requires_a_client_id():
    with pytest.raises(NamoIDError, match="client_id is required"):
        NamoIDClient(client_id="")


def test_fetches_and_caches_the_auth_config():
    seen, client = sync_client(lambda _r: httpx.Response(200, json=CONFIG_PAYLOAD))

    first = client.get_auth_config()
    second = client.get_auth_config()

    assert first.client_id == CLIENT_ID
    assert first.signin_methods == ["email_otp", "passkey"]
    assert second is first, "the config should be cached"
    assert len(seen) == 1
    assert seen[0].url.path == "/v1/auth/config"
    assert seen[0].url.params["client_id"] == CLIENT_ID

    client.get_auth_config(refresh=True)
    assert len(seen) == 2


def test_builds_the_hosted_url_from_the_fetched_config():
    _seen, client = sync_client(lambda _r: httpx.Response(200, json=CONFIG_PAYLOAD))
    transaction = client.create_transaction()

    url = client.hosted_auth_url(
        return_to="https://app.example/callback",
        state=transaction.state,
        completion_mode="confidential",
        code_challenge=transaction.code_challenge,
    )
    query = parse_qs(urlsplit(url).query)

    assert query["client_id"] == [CLIENT_ID]
    assert query["code_challenge"] == [transaction.code_challenge]
    assert query["code_challenge_method"] == ["S256"]
    # The verifier must never appear in the redirect.
    assert transaction.code_verifier not in url


def test_exchanges_a_code_with_a_client_secret():
    import json

    seen, client = sync_client(
        lambda _r: httpx.Response(200, json=TOKEN_PAYLOAD), client_secret=CLIENT_SECRET
    )

    tokens = client.exchange_code(code="c" * 40, code_verifier="v" * 50)

    assert tokens.access_token == "access-token-value"
    assert tokens.refresh_token == "refresh-token-value"
    assert tokens.expires_in == 900
    assert tokens.user_id == "11111111-1111-1111-1111-111111111111"

    body = json.loads(seen[0].content)
    assert seen[0].url.path == "/v1/auth/hosted/exchange"
    assert body["client_secret"] == CLIENT_SECRET
    assert body["code_verifier"] == "v" * 50
    # Unset optional fields are omitted rather than sent as null.
    assert "device_id" not in body


def test_public_exchange_sends_no_secret():
    import json

    seen, client = sync_client(lambda _r: httpx.Response(200, json=TOKEN_PAYLOAD))
    client.exchange_code(code="c" * 40, code_verifier="v" * 50, confidential=False)
    assert "client_secret" not in json.loads(seen[0].content)


def test_confidential_calls_refuse_to_run_without_a_secret():
    _seen, client = sync_client(lambda _r: httpx.Response(200, json=TOKEN_PAYLOAD))
    with pytest.raises(NamoIDError, match="client_secret is required"):
        client.exchange_code(code="c" * 40)
    with pytest.raises(NamoIDError, match="client_secret is required"):
        client.validate_access_token("token")


def test_validates_an_access_token():
    seen, client = sync_client(
        lambda _r: httpx.Response(
            200,
            json={
                "valid": True,
                "user_id": "22222222-2222-2222-2222-222222222222",
                "session_id": "33333333-3333-3333-3333-333333333333",
                "client_id": CLIENT_ID,
                "scopes": ["openid", "email"],
                "error": None,
            },
        ),
        client_secret=CLIENT_SECRET,
    )

    result = client.validate_access_token("access-token-value")

    assert result.valid is True
    assert result.user_id == "22222222-2222-2222-2222-222222222222"
    assert result.scopes == ["openid", "email"]
    assert seen[0].url.path == "/v1/auth/tokens/validate"


def test_refreshes_a_session():
    seen, client = sync_client(lambda _r: httpx.Response(200, json=TOKEN_PAYLOAD))
    tokens = client.refresh("refresh-token-value")
    assert tokens.access_token == "access-token-value"
    assert seen[0].url.path == "/v1/auth/refresh"


def test_revokes_a_session_and_tolerates_an_empty_204():
    seen, client = sync_client(lambda _r: httpx.Response(204))
    client.revoke_session(access_token="access-token-value", refresh_token="refresh-token-value")

    assert seen[0].url.path == "/v1/auth/logout"
    assert seen[0].headers["authorization"] == "Bearer access-token-value"


def test_surfaces_the_api_error_message_and_code():
    _seen, client = sync_client(
        lambda _r: httpx.Response(
            400, json={"error": "invalid_grant", "message": "authorization code expired"}
        ),
        client_secret=CLIENT_SECRET,
    )

    with pytest.raises(NamoIDError) as excinfo:
        client.exchange_code(code="c" * 40)

    error = excinfo.value
    assert "authorization code expired" in str(error)
    assert error.code == "invalid_grant"
    assert error.status == 400
    assert error.detail["error"] == "invalid_grant"


def test_falls_back_to_a_generic_message_for_an_opaque_failure():
    _seen, client = sync_client(lambda _r: httpx.Response(502, text="upstream boom"))
    with pytest.raises(NamoIDError) as excinfo:
        client.refresh("refresh-token-value")
    assert excinfo.value.status == 502
    assert excinfo.value.code == "token_refresh_failed"


def test_reports_a_transport_failure_without_a_status():
    def explode(_request):
        raise httpx.ConnectError("connection refused")

    _seen, client = sync_client(explode)
    with pytest.raises(NamoIDError) as excinfo:
        client.get_auth_config()
    assert excinfo.value.status is None
    assert excinfo.value.code == "auth_config_failed"


def test_rejects_a_token_response_without_an_access_token():
    _seen, client = sync_client(lambda _r: httpx.Response(200, json={"expires_in": 900}))
    with pytest.raises(NamoIDError, match="did not include an access_token"):
        client.refresh("refresh-token-value")


def test_sync_client_works_as_a_context_manager():
    _seen, transport = recorder(lambda _r: httpx.Response(200, json=CONFIG_PAYLOAD))
    with NamoIDClient(client_id=CLIENT_ID, http_client=httpx.Client(transport=transport)) as c:
        assert c.get_auth_config().client_id == CLIENT_ID


# ─── the async client must behave identically ───────────────────────────────


async def test_async_client_mirrors_the_sync_one():
    def handler(request: httpx.Response) -> httpx.Response:
        if request.url.path == "/v1/auth/config":
            return httpx.Response(200, json=CONFIG_PAYLOAD)
        if request.url.path == "/v1/auth/hosted/exchange":
            return httpx.Response(200, json=TOKEN_PAYLOAD)
        if request.url.path == "/v1/auth/logout":
            return httpx.Response(204)
        return httpx.Response(404, json={"error": "not_found"})

    seen, client = async_client(handler, client_secret=CLIENT_SECRET)
    async with client:
        config = await client.get_auth_config()
        assert config.client_id == CLIENT_ID

        url = await client.hosted_auth_url(
            return_to="https://app.example/callback",
            state="state-value",
            completion_mode="confidential",
        )
        assert parse_qs(urlsplit(url).query)["client_id"] == [CLIENT_ID]

        tokens = await client.exchange_code(code="c" * 40, code_verifier="v" * 50)
        assert tokens.access_token == "access-token-value"

        await client.revoke_session(access_token=tokens.access_token)

    assert [r.url.path for r in seen] == [
        "/v1/auth/config",
        "/v1/auth/hosted/exchange",
        "/v1/auth/logout",
    ]


async def test_async_client_surfaces_errors_the_same_way():
    seen, client = async_client(
        lambda _r: httpx.Response(401, json={"error": "invalid_token", "message": "nope"})
    )
    async with client:
        with pytest.raises(NamoIDError) as excinfo:
            await client.refresh("refresh-token-value")
    assert excinfo.value.code == "invalid_token"
    assert excinfo.value.status == 401
    assert len(seen) == 1

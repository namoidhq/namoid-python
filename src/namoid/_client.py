"""Sync and async NamoID clients.

Both share one definition of every request and one response parser, so the two
flavours cannot drift apart. Only the transport differs.
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
from typing import Any, Mapping, Sequence

import httpx

from namoid._errors import NamoIDError
from namoid.hosted_auth import (
    DEFAULT_API_BASE_URL,
    AuthConfig,
    HostedAuthTransaction,
    TokenResponse,
    TokenValidation,
    build_configured_hosted_auth_url,
    create_hosted_auth_transaction,
)
from namoid.oidc import (
    OIDCDiscovery,
    OIDCTransaction,
    build_authorization_url,
    build_logout_url,
    create_oidc_transaction,
    validate_id_token,
)

__all__ = ["AsyncNamoIDClient", "NamoIDClient"]

_DEFAULT_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class _Call:
    """One HTTP call plus how to turn its body into a result."""

    method: str
    path: str
    params: Mapping[str, Any] | None = None
    json: Mapping[str, Any] | None = None
    data: Mapping[str, Any] | None = None
    headers: Mapping[str, str] | None = None
    expect_body: bool = True
    failure_code: str = "namoid_request_failed"
    failure_label: str = "NamoID request"


def _config_call(client_id: str) -> _Call:
    return _Call(
        "GET",
        "/v1/auth/config",
        params={"client_id": client_id},
        failure_code="auth_config_failed",
        failure_label="Auth config request",
    )


def _token_call(
    *,
    endpoint: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
    client_id: str,
    client_secret: str | None,
) -> _Call:
    headers = _oauth_client_headers(client_id, client_secret)
    return _Call(
        "POST",
        endpoint,
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
              "code_verifier": code_verifier, "client_id": client_id},
        headers=headers,
        failure_code="hosted_auth_exchange_failed",
        failure_label="OIDC code exchange",
    )


def _refresh_call(*, endpoint: str, refresh_token: str, client_id: str,
                  client_secret: str | None, scopes: Sequence[str] | None = None) -> _Call:
    data = {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": client_id}
    if scopes:
        data["scope"] = " ".join(dict.fromkeys(scopes))
    return _Call(
        "POST",
        endpoint,
        data=data,
        headers=_oauth_client_headers(client_id, client_secret),
        failure_code="token_refresh_failed",
        failure_label="Token refresh",
    )


def _validate_call(*, token: str, client_id: str | None, client_secret: str | None) -> _Call:
    return _Call(
        "POST",
        "/v1/auth/tokens/validate",
        json=_compact(
            {"token": token, "client_id": client_id, "client_secret": client_secret}
        ),
        failure_code="token_validation_failed",
        failure_label="Token validation",
    )


def _userinfo_call(*, endpoint: str, access_token: str) -> _Call:
    return _Call("GET", endpoint, headers={"authorization": f"Bearer {access_token}"},
                 failure_code="userinfo_failed", failure_label="OIDC UserInfo")


def _revoke_call(*, endpoint: str, token: str, token_type_hint: str | None,
                 client_id: str, client_secret: str | None) -> _Call:
    data = {"token": token, "client_id": client_id}
    if token_type_hint:
        data["token_type_hint"] = token_type_hint
    return _Call("POST", endpoint, data=data,
                 headers=_oauth_client_headers(client_id, client_secret), expect_body=False,
                 failure_code="token_revocation_failed", failure_label="OIDC token revocation")


def _logout_call(*, access_token: str, refresh_token: str | None) -> _Call:
    return _Call(
        "POST",
        "/v1/auth/logout",
        json={"refresh_token": refresh_token},
        headers={"authorization": f"Bearer {access_token}"},
        expect_body=False,
        failure_code="session_revocation_failed",
        failure_label="Session revocation",
    )


def _oauth_client_headers(client_id: str, client_secret: str | None) -> Mapping[str, str]:
    headers = {"content-type": "application/x-www-form-urlencoded"}
    if client_secret:
        credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        headers["authorization"] = f"Basic {credentials}"
    return headers


class _ClientBase:
    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str | None = None,
        api_base_url: str = DEFAULT_API_BASE_URL,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if not client_id:
            raise NamoIDError("client_id is required", code="missing_client_id")
        self._client_id = client_id
        self._client_secret = client_secret
        self._api_base_url = api_base_url.rstrip("/")
        self._timeout = timeout
        self._config: AuthConfig | None = None
        self._discovery: OIDCDiscovery | None = None

    @property
    def client_id(self) -> str:
        return self._client_id

    @staticmethod
    def create_transaction() -> HostedAuthTransaction:
        """Fresh ``state`` and PKCE material for one sign-in attempt."""
        return create_hosted_auth_transaction()

    @staticmethod
    def create_oidc_transaction(redirect_uri: str) -> OIDCTransaction:
        return create_oidc_transaction(redirect_uri)

    def _url(self, path: str) -> str:
        if path.startswith(("https://", "http://")):
            return path
        return f"{self._api_base_url}{path}"

    def _authorization_url(self, discovery: OIDCDiscovery, transaction: OIDCTransaction,
                           scopes: Sequence[str], extra_params: Mapping[str, str] | None) -> str:
        return build_authorization_url(discovery, self._client_id, transaction,
                                       scopes=scopes, extra_params=extra_params)

    def _require_secret(self, provided: str | None) -> str:
        secret = provided or self._client_secret
        if not secret:
            raise NamoIDError(
                "client_secret is required for this call; never place it in browser code",
                code="missing_client_secret",
            )
        return secret

    def _hosted_url(self, config: AuthConfig, kwargs: Mapping[str, Any]) -> str:
        return build_configured_hosted_auth_url(config, **kwargs)


class NamoIDClient(_ClientBase):
    """Blocking NamoID client.

    ``client_secret`` is only needed for confidential calls — code exchange with
    a server-managed session, and token validation. Never pass it in code that
    reaches a browser.
    """

    def __init__(self, *, http_client: httpx.Client | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._http = http_client
        self._owns_http = http_client is None

    def __enter__(self) -> NamoIDClient:
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP client, if this instance created it."""
        if self._owns_http and self._http is not None:
            self._http.close()
            self._http = None

    def get_auth_config(self, *, refresh: bool = False) -> AuthConfig:
        """Fetch and cache the application's browser-safe configuration."""
        if self._config is None or refresh:
            self._config = AuthConfig.from_payload(self._send(_config_call(self._client_id)))
        return self._config

    def get_oidc_discovery(self, *, refresh: bool = False) -> OIDCDiscovery:
        """Fetch and cache the issuer's validated OpenID Connect metadata."""
        if self._discovery is None or refresh:
            issuer = self.get_auth_config(refresh=refresh).issuer.rstrip("/")
            payload = self._send(
                _Call("GET", f"{issuer}/.well-known/openid-configuration",
                      failure_code="oidc_discovery_failed", failure_label="OIDC discovery")
            )
            self._discovery = OIDCDiscovery.from_payload(payload, expected_issuer=issuer)
        return self._discovery

    def authorization_url(self, transaction: OIDCTransaction, *,
                          scopes: Sequence[str] = ("openid", "profile", "email"),
                          extra_params: Mapping[str, str] | None = None) -> str:
        """Build a standard OIDC Authorization Code + PKCE URL."""
        return self._authorization_url(self.get_oidc_discovery(), transaction, scopes, extra_params)

    def hosted_auth_url(self, **kwargs: Any) -> str:
        """Build the Hosted Auth URL for this application.

        Accepts the keyword arguments of
        :func:`namoid.hosted_auth.build_configured_hosted_auth_url`.
        """
        return self._hosted_url(self.get_auth_config(), kwargs)

    def exchange_code(
        self,
        *,
        code: str,
        code_verifier: str,
        redirect_uri: str,
        client_secret: str | None = None,
        confidential: bool | None = None,
    ) -> TokenResponse:
        """Exchange a one-time Hosted Auth code for a NamoID session.

        Args:
            confidential: When true (the default) a Client Secret is required,
                matching ``completion_mode="confidential"`` on the redirect. Pass
                false for the browser-only PKCE flow.
        """
        secret = client_secret or self._client_secret
        if confidential is True:
            secret = self._require_secret(client_secret)
        discovery = self.get_oidc_discovery()
        payload = self._send(
            _token_call(
                endpoint=discovery.token_endpoint,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                client_id=self._client_id,
                client_secret=secret,
            )
        )
        return TokenResponse.from_payload(payload)

    def refresh(self, refresh_token: str, *, scopes: Sequence[str] | None = None,
                client_secret: str | None = None) -> TokenResponse:
        """Rotate a refresh token for a new session."""
        discovery = self.get_oidc_discovery()
        return TokenResponse.from_payload(self._send(_refresh_call(
            endpoint=discovery.token_endpoint, refresh_token=refresh_token,
            client_id=self._client_id, client_secret=client_secret or self._client_secret,
            scopes=scopes,
        )))

    def user_info(self, access_token: str) -> Mapping[str, Any]:
        return self._send(_userinfo_call(
            endpoint=self.get_oidc_discovery().userinfo_endpoint, access_token=access_token
        ))

    def validate_id_token(self, id_token: str, *, nonce: str) -> Mapping[str, Any]:
        discovery = self.get_oidc_discovery()
        jwks = self._send(_Call("GET", discovery.jwks_uri, failure_code="jwks_unavailable",
                                failure_label="OIDC signing keys"))
        return validate_id_token(id_token, jwks=jwks, issuer=discovery.issuer,
                                 client_id=self._client_id, nonce=nonce)

    def revoke_token(self, token: str, *, token_type_hint: str | None = None,
                     client_secret: str | None = None) -> None:
        discovery = self.get_oidc_discovery()
        if not discovery.revocation_endpoint:
            raise NamoIDError("The issuer does not advertise token revocation",
                              code="revocation_unavailable")
        self._send(_revoke_call(
            endpoint=discovery.revocation_endpoint, token=token,
            token_type_hint=token_type_hint, client_id=self._client_id,
            client_secret=client_secret or self._client_secret,
        ))

    def logout_url(self, *, id_token_hint: str, post_logout_redirect_uri: str | None = None,
                   state: str | None = None) -> str:
        return build_logout_url(self.get_oidc_discovery(), id_token_hint=id_token_hint,
                                post_logout_redirect_uri=post_logout_redirect_uri, state=state)

    def validate_access_token(
        self, token: str, *, client_secret: str | None = None
    ) -> TokenValidation:
        """Validate an access token with this application's credentials.

        Server-side only. For an MCP server, verify tokens locally instead — see
        :mod:`namoid.mcp`, which needs no credentials and no round trip.
        """
        secret = self._require_secret(client_secret)
        payload = self._send(
            _validate_call(token=token, client_id=self._client_id, client_secret=secret)
        )
        return TokenValidation.from_payload(payload)

    def revoke_session(self, *, access_token: str, refresh_token: str | None = None) -> None:
        """Revoke the NamoID session behind ``access_token``.

        Omitting ``refresh_token`` revokes every session for the user.
        """
        self._send(_logout_call(access_token=access_token, refresh_token=refresh_token))

    def _send(self, call: _Call) -> Any:
        if self._http is None:
            self._http = httpx.Client(timeout=self._timeout)
            self._owns_http = True
        try:
            response = self._http.request(
                call.method,
                self._url(call.path),
                params=dict(call.params or {}) or None,
                json=dict(call.json) if call.json is not None else None,
                data=dict(call.data) if call.data is not None else None,
                headers={"accept": "application/json", **(call.headers or {})},
            )
        except httpx.HTTPError as exc:
            raise NamoIDError(
                f"{call.failure_label} could not be sent: {exc}", code=call.failure_code
            ) from exc
        return _handle(response, call)


class AsyncNamoIDClient(_ClientBase):
    """Async NamoID client. Mirrors :class:`NamoIDClient` exactly."""

    def __init__(self, *, http_client: httpx.AsyncClient | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._http = http_client
        self._owns_http = http_client is None

    async def __aenter__(self) -> AsyncNamoIDClient:
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying HTTP client, if this instance created it."""
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None

    async def get_auth_config(self, *, refresh: bool = False) -> AuthConfig:
        if self._config is None or refresh:
            self._config = AuthConfig.from_payload(
                await self._send(_config_call(self._client_id))
            )
        return self._config

    async def get_oidc_discovery(self, *, refresh: bool = False) -> OIDCDiscovery:
        if self._discovery is None or refresh:
            issuer = (await self.get_auth_config(refresh=refresh)).issuer.rstrip("/")
            payload = await self._send(
                _Call("GET", f"{issuer}/.well-known/openid-configuration",
                      failure_code="oidc_discovery_failed", failure_label="OIDC discovery")
            )
            self._discovery = OIDCDiscovery.from_payload(payload, expected_issuer=issuer)
        return self._discovery

    async def authorization_url(self, transaction: OIDCTransaction, *,
                                scopes: Sequence[str] = ("openid", "profile", "email"),
                                extra_params: Mapping[str, str] | None = None) -> str:
        return self._authorization_url(
            await self.get_oidc_discovery(), transaction, scopes, extra_params
        )

    async def hosted_auth_url(self, **kwargs: Any) -> str:
        return self._hosted_url(await self.get_auth_config(), kwargs)

    async def exchange_code(
        self,
        *,
        code: str,
        code_verifier: str,
        redirect_uri: str,
        client_secret: str | None = None,
        confidential: bool | None = None,
    ) -> TokenResponse:
        secret = client_secret or self._client_secret
        if confidential is True:
            secret = self._require_secret(client_secret)
        discovery = await self.get_oidc_discovery()
        payload = await self._send(
            _token_call(
                endpoint=discovery.token_endpoint,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                client_id=self._client_id,
                client_secret=secret,
            )
        )
        return TokenResponse.from_payload(payload)

    async def refresh(self, refresh_token: str, *, scopes: Sequence[str] | None = None,
                      client_secret: str | None = None) -> TokenResponse:
        discovery = await self.get_oidc_discovery()
        return TokenResponse.from_payload(await self._send(_refresh_call(
            endpoint=discovery.token_endpoint, refresh_token=refresh_token,
            client_id=self._client_id, client_secret=client_secret or self._client_secret,
            scopes=scopes,
        )))

    async def user_info(self, access_token: str) -> Mapping[str, Any]:
        return await self._send(_userinfo_call(
            endpoint=(await self.get_oidc_discovery()).userinfo_endpoint,
            access_token=access_token,
        ))

    async def validate_id_token(self, id_token: str, *, nonce: str) -> Mapping[str, Any]:
        discovery = await self.get_oidc_discovery()
        jwks = await self._send(_Call("GET", discovery.jwks_uri,
                                      failure_code="jwks_unavailable",
                                      failure_label="OIDC signing keys"))
        return validate_id_token(id_token, jwks=jwks, issuer=discovery.issuer,
                                 client_id=self._client_id, nonce=nonce)

    async def revoke_token(self, token: str, *, token_type_hint: str | None = None,
                           client_secret: str | None = None) -> None:
        discovery = await self.get_oidc_discovery()
        if not discovery.revocation_endpoint:
            raise NamoIDError("The issuer does not advertise token revocation",
                              code="revocation_unavailable")
        await self._send(_revoke_call(
            endpoint=discovery.revocation_endpoint, token=token,
            token_type_hint=token_type_hint, client_id=self._client_id,
            client_secret=client_secret or self._client_secret,
        ))

    async def logout_url(self, *, id_token_hint: str,
                         post_logout_redirect_uri: str | None = None,
                         state: str | None = None) -> str:
        return build_logout_url(await self.get_oidc_discovery(), id_token_hint=id_token_hint,
                                post_logout_redirect_uri=post_logout_redirect_uri, state=state)

    async def validate_access_token(
        self, token: str, *, client_secret: str | None = None
    ) -> TokenValidation:
        secret = self._require_secret(client_secret)
        payload = await self._send(
            _validate_call(token=token, client_id=self._client_id, client_secret=secret)
        )
        return TokenValidation.from_payload(payload)

    async def revoke_session(
        self, *, access_token: str, refresh_token: str | None = None
    ) -> None:
        await self._send(_logout_call(access_token=access_token, refresh_token=refresh_token))

    async def _send(self, call: _Call) -> Any:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self._timeout)
            self._owns_http = True
        try:
            response = await self._http.request(
                call.method,
                self._url(call.path),
                params=dict(call.params or {}) or None,
                json=dict(call.json) if call.json is not None else None,
                data=dict(call.data) if call.data is not None else None,
                headers={"accept": "application/json", **(call.headers or {})},
            )
        except httpx.HTTPError as exc:
            raise NamoIDError(
                f"{call.failure_label} could not be sent: {exc}", code=call.failure_code
            ) from exc
        return _handle(response, call)


def _handle(response: httpx.Response, call: _Call) -> Any:
    if response.is_success:
        if not call.expect_body or response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise NamoIDError(
                f"{call.failure_label} returned a non-JSON body",
                status=response.status_code,
                code=call.failure_code,
            ) from exc

    body = _safe_json(response)
    raise NamoIDError(
        _error_message(body) or f"{call.failure_label} failed with {response.status_code}",
        status=response.status_code,
        code=_error_code(body) or call.failure_code,
        detail=body,
    )


def _safe_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def _error_message(body: Any) -> str | None:
    if isinstance(body, Mapping):
        for key in ("message", "detail"):
            value = body.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def _error_code(body: Any) -> str | None:
    if isinstance(body, Mapping):
        value = body.get("error")
        if isinstance(value, str) and value:
            return value
    return None


def _compact(values: Mapping[str, Any]) -> dict:
    """Drop unset keys so the API sees an absent field, not an explicit null."""
    return {key: value for key, value in values.items() if value is not None}

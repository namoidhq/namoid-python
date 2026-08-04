"""Sync and async NamoID clients.

Both share one definition of every request and one response parser, so the two
flavours cannot drift apart. Only the transport differs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

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

__all__ = ["AsyncNamoIDClient", "NamoIDClient"]

_DEFAULT_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class _Call:
    """One HTTP call plus how to turn its body into a result."""

    method: str
    path: str
    params: Mapping[str, Any] | None = None
    json: Mapping[str, Any] | None = None
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


def _exchange_call(
    *,
    code: str,
    code_verifier: str | None,
    client_id: str | None,
    client_secret: str | None,
    device_id: str | None,
) -> _Call:
    return _Call(
        "POST",
        "/v1/auth/hosted/exchange",
        json=_compact(
            {
                "code": code,
                "code_verifier": code_verifier,
                "device_id": device_id,
                "client_id": client_id,
                "client_secret": client_secret,
            }
        ),
        failure_code="hosted_auth_exchange_failed",
        failure_label="Hosted Auth exchange",
    )


def _refresh_call(refresh_token: str) -> _Call:
    return _Call(
        "POST",
        "/v1/auth/refresh",
        json={"refresh_token": refresh_token},
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

    @property
    def client_id(self) -> str:
        return self._client_id

    @staticmethod
    def create_transaction() -> HostedAuthTransaction:
        """Fresh ``state`` and PKCE material for one sign-in attempt."""
        return create_hosted_auth_transaction()

    def _url(self, path: str) -> str:
        return f"{self._api_base_url}{path}"

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
        code_verifier: str | None = None,
        client_secret: str | None = None,
        device_id: str | None = None,
        confidential: bool = True,
    ) -> TokenResponse:
        """Exchange a one-time Hosted Auth code for a NamoID session.

        Args:
            confidential: When true (the default) a Client Secret is required,
                matching ``completion_mode="confidential"`` on the redirect. Pass
                false for the browser-only PKCE flow.
        """
        secret = self._require_secret(client_secret) if confidential else None
        payload = self._send(
            _exchange_call(
                code=code,
                code_verifier=code_verifier,
                client_id=self._client_id,
                client_secret=secret,
                device_id=device_id,
            )
        )
        return TokenResponse.from_payload(payload)

    def refresh(self, refresh_token: str) -> TokenResponse:
        """Rotate a refresh token for a new session."""
        return TokenResponse.from_payload(self._send(_refresh_call(refresh_token)))

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

    async def hosted_auth_url(self, **kwargs: Any) -> str:
        return self._hosted_url(await self.get_auth_config(), kwargs)

    async def exchange_code(
        self,
        *,
        code: str,
        code_verifier: str | None = None,
        client_secret: str | None = None,
        device_id: str | None = None,
        confidential: bool = True,
    ) -> TokenResponse:
        secret = self._require_secret(client_secret) if confidential else None
        payload = await self._send(
            _exchange_call(
                code=code,
                code_verifier=code_verifier,
                client_id=self._client_id,
                client_secret=secret,
                device_id=device_id,
            )
        )
        return TokenResponse.from_payload(payload)

    async def refresh(self, refresh_token: str) -> TokenResponse:
        return TokenResponse.from_payload(await self._send(_refresh_call(refresh_token)))

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

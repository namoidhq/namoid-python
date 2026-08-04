"""A stand-in NamoID environment: RFC 8414 discovery plus a JWKS endpoint.

Served over loopback in a background thread so the code under test exercises its
real httpx paths, including JWKS caching and refetch on an unknown ``kid``.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from joserfc import jwk, jwt

DEFAULT_KID = "test-key-1"


@dataclass
class FakeAuthorizationServer:
    issuer: str
    keys: dict = field(default_factory=dict)
    """kid -> RSAKey, all published in the JWKS document."""

    declared_issuer: str | None = None
    """Overrides the ``issuer`` claim in the discovery document."""

    omit_jwks_uri: bool = False
    jwks_request_count: int = 0

    def add_key(self, kid: str) -> jwk.RSAKey:
        key = jwk.RSAKey.generate_key(2048, parameters={"kid": kid, "alg": "RS256"})
        self.keys[kid] = key
        return key

    def discovery_document(self) -> dict:
        document = {
            "issuer": self.declared_issuer or self.issuer,
            "authorization_endpoint": f"{self.issuer}/oauth/authorize",
            "token_endpoint": f"{self.issuer}/v1/oauth/token",
            "jwks_uri": f"{self.issuer}/v1/oauth/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "client_id_metadata_document_supported": True,
        }
        if self.omit_jwks_uri:
            del document["jwks_uri"]
        return document

    def jwks_document(self) -> dict:
        return {"keys": [key.as_dict(private=False) for key in self.keys.values()]}

    def mint(
        self,
        *,
        audience: str,
        scope: str = "",
        subject: str | None = "user-uuid-1",
        client_id: str | None = "https://client.example/oauth/metadata.json",
        token_use: str | None = "access",
        issuer: str | None = None,
        kid: str = DEFAULT_KID,
        expires_in: int = 300,
    ) -> str:
        """Mint a token shaped like NamoID's access-token contract."""
        now = int(time.time())
        claims: dict = {
            "iss": issuer or self.issuer,
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + expires_in,
            "tid": "tenant-uuid",
            "pid": "project-uuid",
            "eid": "environment-uuid",
            "jti": "token-uuid",
            "scope": scope,
        }
        if subject is not None:
            claims["sub"] = subject
        if client_id is not None:
            claims["client_id"] = client_id
        if token_use is not None:
            claims["token_use"] = token_use
        return jwt.encode({"alg": "RS256", "kid": kid}, claims, self.keys[kid])


@pytest.fixture
def authorization_server():
    state = FakeAuthorizationServer(issuer="")
    state.add_key(DEFAULT_KID)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's naming
            if self.path == "/.well-known/oauth-authorization-server":
                return self._json(state.discovery_document())
            if self.path == "/v1/oauth/jwks.json":
                state.jwks_request_count += 1
                return self._json(state.jwks_document())
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"{}")

        def _json(self, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):  # silence per-request logging
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    state.issuer = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

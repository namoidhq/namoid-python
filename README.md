# namoid

[![PyPI version](https://img.shields.io/pypi/v/namoid.svg)](https://pypi.org/project/namoid/)
[![Python versions](https://img.shields.io/pypi/pyversions/namoid.svg)](https://pypi.org/project/namoid/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/namoidhq/namoid-python/blob/main/LICENSE)

Python SDK for [NamoID](https://namoid.in) — enterprise identity for India (OAuth 2.1 / OpenID Connect): SSO, MFA, passkeys, and India verification (DigiLocker, Aadhaar, WhatsApp OTP, Truecaller) with a DPDP-ready audit trail.

## Install

```bash
pip install namoid
```

The base package has no dependencies. Protecting an MCP server adds an extra:

```bash
pip install "namoid[fastmcp]"   # protect a FastMCP server (Python 3.11+)
pip install "namoid[mcp]"       # the same core, without FastMCP
```

Python 3.10 or newer. The FastMCP extra requires 3.11.

## Protect an MCP server

NamoID is the authorization server. Your MCP server is the protected resource.
An MCP host — Claude, ChatGPT, Cursor, VS Code — is the OAuth client, and the
signed-in human is the resource owner. NamoID authenticates that human, records
consent, and issues a short-lived token limited to your server and to the
actions approved; this package validates and enforces it.

No NamoID credentials are needed: a resource server only consumes public
discovery metadata and JWKS.

```python
from fastmcp import FastMCP
from namoid.mcp.fastmcp import create_namoid_auth, current_caller, require_namoid_scopes

# Console -> Environment -> MCP Authorization -> Integration details.
# Discovery runs here, so a wrong issuer or resource fails at startup rather
# than as an opaque 401 on the first tool call.
auth = create_namoid_auth(
    issuer="https://acme-test.id.namoid.in",
    resource="https://mcp.acme.example/mcp",   # exactly as registered as the audience
    resource_name="Acme Finance MCP",
    scopes_supported=["customers:read", "invoices:read"],
)

mcp = FastMCP(name="acme-finance-mcp", auth=auth.provider)


@mcp.tool
@require_namoid_scopes(auth, "refunds:create")
def issue_refund(invoice_id: str, amount_minor: int) -> dict:
    caller = current_caller(auth)          # the NamoID user who consented
    assert_refund_allowed(caller.subject, invoice_id, amount_minor)
    return refund(invoice_id, amount_minor)


if __name__ == "__main__":
    # The path comes from the resource URL, so the endpoint matches the audience.
    mcp.run(transport="http", path=auth.mcp_path)
```

A scope is permission to **attempt** an action. `refunds:create` does not mean
this user may refund another organization's invoice or exceed your refund
policy. Ownership, limits, and every other business rule stay in the handler.

When a scope is missing, the tool answers with an `insufficient_scope` result
naming the missing scopes, the resource, and the metadata URL — what a host
needs to start incremental authorization. The tool stays visible in
`tools/list`, because hiding it would leave the host unable to ask for access.
Use FastMCP's own `require_scopes` when hiding a capability is the goal.

### What it validates

Every token must satisfy all of:

| Check | Why |
|---|---|
| `RS256` from the environment's JWKS | The only algorithm NamoID issues |
| Exact `iss` | A token from another issuer is not yours |
| Exact `aud` | A token minted for MCP server A must fail on server B |
| `exp` / `nbf`, 30s tolerance | Configurable via `clock_tolerance_seconds` |
| `token_use == "access"` | An ID token must never be an API token |
| `sub` and `client_id` present | Without `sub`, every caller is one identity |

Discovery also checks that the issuer's metadata declares the issuer you asked
for — RFC 9700 mix-up defence — and reads `jwks_uri` from it rather than
hard-coding a key location. The key set is cached, and refetched when a token
arrives with an unrecognised `kid` so key rotation is picked up without a
restart.

### Without FastMCP

`namoid.mcp` imports no MCP framework, so it can back the official MCP Python
SDK, a bare Starlette app, or a test:

```python
from namoid.mcp import create_namoid_mcp_auth, NamoIDMcpTokenError

auth = await create_namoid_mcp_auth(
    issuer="https://acme-test.id.namoid.in",
    resource="https://mcp.acme.example/mcp",
    scopes_supported=["invoices:read"],
)

# Publish auth.protected_resource_metadata at auth.metadata_path (RFC 9728),
# and answer an unauthenticated call with a WWW-Authenticate challenge
# pointing at auth.metadata_url.
try:
    caller = await auth.verify_access_token(bearer_token)
except NamoIDMcpTokenError:
    ...  # 401 + challenge
```

`create_namoid_mcp_auth_sync` is the blocking form, for servers built at module
import where there is no event loop to await on.

### Client onboarding

NamoID resolves MCP clients by pre-registration or Client ID Metadata Document
(CIMD). Dynamic Client Registration is not available for customer-owned MCP
resources, so a host that can only do DCR cannot connect yet.

## Examples

Complete runnable servers, including a TypeScript equivalent:
[namoid-examples/mcp-authorization](https://github.com/namoidhq/namoid-examples/tree/main/mcp-authorization).

For the rest of the SDK, see the integration guides and API reference at
[docs.namoid.in](https://docs.namoid.in).

## Develop

```bash
python -m venv .venv && .venv/bin/pip install -e ".[fastmcp]" pytest pytest-asyncio
.venv/bin/python -m pytest tests/ -q
```

## Links

- Website — [namoid.in](https://namoid.in)
- Docs — [docs.namoid.in](https://docs.namoid.in)
- Examples — [namoidhq/namoid-examples](https://github.com/namoidhq/namoid-examples)
- Contact — [hello@namoid.in](mailto:hello@namoid.in)
- Issues — [github.com/namoidhq/namoid-python/issues](https://github.com/namoidhq/namoid-python/issues)

## License

[MIT](https://github.com/namoidhq/namoid-python/blob/main/LICENSE) © PolyMindsLabs Pvt. Ltd.

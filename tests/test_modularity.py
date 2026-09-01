"""The two surfaces stay independent.

Each test runs in a fresh interpreter, because `sys.modules` is process-global
and any earlier import in this test session would mask the thing being checked.
"""

from __future__ import annotations

import subprocess
import sys

import pytest


def run(source: str) -> str:
    """Execute ``source`` in a clean interpreter and return its stdout."""
    result = subprocess.run(
        [sys.executable, "-c", source],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    return result.stdout.strip()


def test_importing_the_package_loads_neither_surface():
    assert (
        run(
            """
import sys
import namoid

loaded = [m for m in sys.modules if m.startswith("namoid")]
assert loaded == ["namoid"], f"importing namoid pulled in {loaded}"
assert "httpx" not in sys.modules, "importing namoid should not load httpx"
assert "joserfc" not in sys.modules, "importing namoid should not load joserfc"
print("ok")
"""
        )
        == "ok"
    )


def test_lazy_exports_resolve_and_are_discoverable():
    assert (
        run(
            """
import sys
import namoid

# Advertised before anything is imported, so editors and dir() see the surface.
assert "NamoIDClient" in dir(namoid)
assert "NamoIDClient" in namoid.__all__
assert "namoid._client" not in sys.modules

client_cls = namoid.NamoIDClient
assert client_cls.__name__ == "NamoIDClient"
assert "namoid._client" in sys.modules, "naming the export should load its module"

# Second access is served from the module globals, not __getattr__ again.
assert namoid.NamoIDClient is client_cls

try:
    namoid.NotAThing
except AttributeError as exc:
    assert "NotAThing" in str(exc)
else:
    raise AssertionError("unknown attributes must still raise AttributeError")
print("ok")
"""
        )
        == "ok"
    )


def test_hosted_auth_never_loads_the_mcp_surface():
    assert (
        run(
            """
import sys
from namoid import NamoIDClient, create_hosted_auth_transaction

create_hosted_auth_transaction()
NamoIDClient(client_id="namoid_client_test_aaaaaaaaaaaaaaaa")

assert "namoid.mcp" not in sys.modules, "Hosted Auth must not load the MCP surface"
assert "joserfc" not in sys.modules, "Hosted Auth must not need the mcp extra"
assert "fastmcp" not in sys.modules
print("ok")
"""
        )
        == "ok"
    )


def test_mcp_core_never_loads_hosted_auth_or_a_framework():
    pytest.importorskip("joserfc", reason="requires the mcp extra")
    assert (
        run(
            """
import sys
import namoid.mcp

assert "namoid._client" not in sys.modules, "the MCP core must not load the Hosted Auth client"
assert "namoid.hosted_auth" not in sys.modules, "the MCP core must not load Hosted Auth"
assert "fastmcp" not in sys.modules, "the MCP core must not require an MCP framework"
assert "mcp" not in sys.modules
assert "starlette" not in sys.modules
print("ok")
"""
        )
        == "ok"
    )


def test_mcp_core_carries_no_framework_imports_even_transitively():
    """A stricter form of the above: block the frameworks at import time."""
    pytest.importorskip("joserfc", reason="requires the mcp extra")
    assert (
        run(
            """
import builtins
import sys

blocked = {"fastmcp", "starlette", "mcp", "namoid.hosted_auth", "namoid._client"}
real_import = builtins.__import__

def guarded(name, *args, **kwargs):
    if name in blocked or any(name.startswith(b + ".") for b in blocked):
        raise AssertionError(f"the MCP core must not import {name}")
    return real_import(name, *args, **kwargs)

builtins.__import__ = guarded
try:
    import namoid.mcp
    namoid.mcp.protected_resource_metadata_path("https://mcp.acme.example/mcp")
finally:
    builtins.__import__ = real_import
print("ok")
"""
        )
        == "ok"
    )


def test_the_fastmcp_adapter_is_opt_in_and_builds_on_the_core():
    pytest.importorskip("fastmcp", reason="requires the fastmcp extra")
    assert (
        run(
            """
import sys
import namoid.mcp.fastmcp

# The adapter is the only place a framework appears.
assert "fastmcp" in sys.modules
assert "namoid.mcp" in sys.modules, "the adapter must build on the shared core"
assert "namoid._client" not in sys.modules, "the adapter must not load Hosted Auth"
assert "namoid.hosted_auth" not in sys.modules
print("ok")
"""
        )
        == "ok"
    )


def test_one_error_type_catches_both_surfaces():
    pytest.importorskip("joserfc", reason="requires the mcp extra")
    assert (
        run(
            """
from namoid import NamoIDError
from namoid.mcp import NamoIDMcpConfigurationError, NamoIDMcpTokenError

assert issubclass(NamoIDMcpConfigurationError, NamoIDError)
assert issubclass(NamoIDMcpTokenError, NamoIDError)

# Sharing a base must not change the message a resource server surfaces.
assert str(NamoIDMcpTokenError("token has expired")) == "token has expired"
print("ok")
"""
        )
        == "ok"
    )


def test_the_mcp_extra_reports_a_clear_error_when_missing():
    """`namoid.mcp` without its extra must name the dependency, not fail obscurely."""
    assert (
        run(
            """
import builtins
import sys

real_import = builtins.__import__

def without_joserfc(name, *args, **kwargs):
    if name == "joserfc" or name.startswith("joserfc."):
        raise ModuleNotFoundError("No module named 'joserfc'", name="joserfc")
    return real_import(name, *args, **kwargs)

builtins.__import__ = without_joserfc
try:
    import namoid.mcp
except ModuleNotFoundError as exc:
    assert exc.name == "joserfc", exc.name
else:
    raise AssertionError("expected the missing extra to surface")
finally:
    builtins.__import__ = real_import
print("ok")
"""
        )
        == "ok"
    )

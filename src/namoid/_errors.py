"""The error type every NamoID call raises."""

from __future__ import annotations

from typing import Any

__all__ = ["NamoIDError"]


class NamoIDError(Exception):
    """A NamoID request failed, or was refused before being sent.

    Attributes:
        status: HTTP status, or ``None`` when the call never reached the API.
        code: The API's machine-readable ``error`` code where one was returned,
            otherwise a local code such as ``"missing_client_id"``.
        detail: The parsed response body, when there was one.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        code: str | None = None,
        detail: Any = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.detail = detail

    def __str__(self) -> str:
        base = super().__str__()
        if self.code and self.status is not None:
            return f"{base} (status={self.status}, code={self.code})"
        if self.code:
            return f"{base} (code={self.code})"
        if self.status is not None:
            return f"{base} (status={self.status})"
        return base

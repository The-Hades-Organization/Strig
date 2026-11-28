"""Errors raised by the engine: one `code`, the same stable `errorCode` as the JavaScript binding."""

from __future__ import annotations

from typing import Any, List


class StrigError(Exception):
    """A failed call. `code` is stable across versions (`INVALID_ARGUMENT`, `REENTRANT_CALL`, ...)."""

    code: str
    message: str

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return self.message


class DslError(StrigError):
    """A failure of the policy language. `diagnostics` are the positioned problems."""

    diagnostics: List[Any]

    def __init__(self, code: str, message: str, diagnostics: List[Any] | None = None) -> None:
        super().__init__(code, message)
        self.diagnostics = list(diagnostics or [])

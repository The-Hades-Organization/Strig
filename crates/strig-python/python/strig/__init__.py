"""Strig authorization engine: the same engine and JSON spec as the Rust and JavaScript APIs."""

from typing import Any, Dict, List

from . import dsl
from ._native import Context, Engine, Exclusive, audit_estimate, verify_audit_chain
from .errors import DslError, StrigError



def scope_from_string(text: str) -> Dict[str, Any]:
    """A resource from `"project:p1/org:o1"` (narrowest first); a segment without `:` has no id."""
    path: List[Dict[str, str]] = []
    for segment in filter(None, text.split("/")):
        kind, sep, ident = segment.partition(":")
        path.append({"kind": kind, "id": ident} if sep else {"kind": kind})
    return {"path": path}


__all__ = [
    "Context",
    "DslError",
    "Engine",
    "Exclusive",
    "StrigError",
    "audit_estimate",
    "dsl",
    "scope_from_string",
    "verify_audit_chain",
]

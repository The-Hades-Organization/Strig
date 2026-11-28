"""The policy language: compile, print, convert and format policy text, and load a project.

Every function raises `DslError` (a `StrigError`) with `code` and positioned `diagnostics`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import _native
from .errors import DslError

__all__ = [
    "compile",
    "print",
    "convert",
    "format",
    "is_formatted",
    "load_project",
    "load_project_dir",
]


def _open(envelope: Dict[str, Any]) -> Any:
    if envelope["ok"]:
        return envelope["value"]
    raise DslError(envelope["code"], envelope["message"], envelope["diagnostics"])


def _options(file: Optional[str]) -> Optional[Dict[str, Any]]:
    return None if file is None else {"file": file}


def compile(text: str, file: Optional[str] = None) -> Dict[str, Any]:
    """The canonical policy document of `text`; `file` names it in the diagnostics."""
    result: Dict[str, Any] = _open(_native.dsl_compile(text, _options(file)))
    return result


def print(policy: Dict[str, Any], language: str) -> str:  # noqa: A001
    """The text of `policy` in `language` (`blocks`, `rules` or `actors`)."""
    result: str = _open(_native.dsl_print(policy, language))
    return result


def convert(text: str, language: str) -> str:
    """`text` rewritten in another syntax."""
    result: str = _open(_native.dsl_convert(text, language))
    return result


def format(text: str, file: Optional[str] = None) -> str:  # noqa: A001
    """`text` in the canonical layout of the syntax it declares."""
    result: str = _open(_native.dsl_format(text, _options(file)))
    return result


def is_formatted(text: str, file: Optional[str] = None) -> bool:
    """Whether `text` is already in the canonical layout."""
    result: bool = _open(_native.dsl_is_formatted(text, _options(file)))
    return result


def load_project(sources: List[Dict[str, str]]) -> Dict[str, Any]:
    """One policy from `[{ "path": ..., "text": ... }]`."""
    result: Dict[str, Any] = _open(_native.dsl_load_project(sources))
    return result


def load_project_dir(directory: str) -> Dict[str, Any]:
    """One policy from the `.strig` files of a directory."""
    result: Dict[str, Any] = _open(_native.dsl_load_project_dir(str(directory)))
    return result


def run_tests(policy: Dict[str, Any], tests: List[Any]) -> Dict[str, Any]:
    """Run test files (`TestFile` dicts or their JSON text) against a policy, without IO.

    Returns the report: `{"results": [...], ...}`, one entry per case with its `outcome`.
    """
    result: Dict[str, Any] = _open(_native.dsl_run_tests(policy, tests))
    return result

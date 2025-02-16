"""Init file for the Mitsubishi Connect client."""

from collections.abc import Callable
from typing import Any, TypeVar

T = TypeVar("T")


def from_int(x: Any) -> int:
    """Get an int from an object."""
    if not isinstance(x, int) or isinstance(x, bool):
        msg = f"Expected int, got {type(x)}"
        raise TypeError(msg)
    return x


def from_str(x: Any) -> str:
    """Get a str from an object."""
    if not isinstance(x, str):
        msg = f"Expected str, got {type(x)}"
        raise TypeError(msg)
    return x


def from_str_none(x: Any) -> str | None:
    """Get a str from an object."""
    if x is None:
        return None
    return from_str(x)


def from_list(f: Callable[[Any], T], x: Any) -> list[T]:
    """Get a list from an object."""
    if not isinstance(x, list):
        msg = f"Expected list, got {type(x)}"
        raise TypeError(msg)
    return [f(y) for y in x]

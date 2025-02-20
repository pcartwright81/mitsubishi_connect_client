"""Init file for the Mitsubishi Connect client."""

from collections.abc import Callable
from datetime import date, datetime
from typing import Any, TypeVar

from dateutil import parser

T = TypeVar("T")


def from_int(x: Any) -> int:
    """Get an int from an object."""
    if not isinstance(x, str):
        msg = f"Expected int, got {type(x)}"
        raise TypeError(msg)
    return int(x)


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


def from_bool(x: Any) -> bool:
    """Get a bool from an object."""
    if not isinstance(x, bool):
        msg = f"Expected bool, got {type(x)}"
        raise TypeError(msg)
    return x


def from_datetime(x: Any) -> datetime:
    """Get a datetime from an object."""
    return parser.parse(x)


def from_date(x: Any) -> date:
    """Get a date from an object."""
    return parser.parse(x).date()


def from_float(x: Any) -> float:
    """Get a float from an object."""
    if not isinstance(x, float | int) and not isinstance(x, bool):
        msg = f"Expected float, got {type(x)}"
        raise TypeError(msg)
    return float(x)

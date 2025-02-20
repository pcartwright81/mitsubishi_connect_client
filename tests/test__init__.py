"""Test the init file for the mitsubishi connect client."""

import unittest
from typing import TypeVar

import pytest

from mitsubishi_connect_client import (
    from_bool,
    from_float,
    from_int,
    from_list,
    from_str,
    from_str_none,
)

T = TypeVar("T")


class TestDataConversions(unittest.TestCase):
    """Test the data conversions."""

    def test_from_int_valid(self) -> None:
        """Tests that `from_int` correctly converts a valid integer value."""
        self.assertEqual(from_int("5"), 5)

    def test_from_int_invalid_type(self) -> None:
        """Tests that `from_int` raises a TypeError for an invalid type."""
        with pytest.raises(TypeError):
            from_int(12345)

    def test_from_int_invalid_bool(self) -> None:
        """Tests that `from_int` raises a TypeError for a boolean input."""
        with pytest.raises(TypeError):
            from_int(True)  # noqa: FBT003

    def test_from_str_valid(self) -> None:
        """Tests that `from_str` correctly converts a valid string value."""
        self.assertEqual(from_str("hello"), "hello")

    def test_from_str_invalid(self) -> None:
        """Tests that `from_str` raises a TypeError for an invalid type."""
        with pytest.raises(TypeError):
            from_str(5)

    def test_from_str_none_valid(self) -> None:
        """Tests that `from_str_none` correctly converts a valid string value."""
        self.assertEqual(from_str_none("hello"), "hello")

    def test_from_str_none_none(self) -> None:
        """Tests that `from_str_none` correctly handles a None input."""
        self.assertIsNone(from_str_none(None))

    def test_from_str_none_invalid(self) -> None:
        """Tests that `from_str_none` raises a TypeError for an invalid type."""
        with pytest.raises(TypeError):
            from_str_none(5)

    def test_from_list_valid(self) -> None:
        """Tests that `from_list` correctly converts a list of valid integer values."""
        self.assertEqual(from_list(from_int, ["1", "2", "3"]), [1, 2, 3])

    def test_from_list_invalid_type(self) -> None:
        """Tests that `from_list` raises a TypeError for an invalid list type."""
        with pytest.raises(TypeError):
            from_list(from_int, "not a list")

    def test_from_list_invalid_element(self) -> None:
        """Tests that `from_list` raises a TypeError for an invalid element type."""
        with pytest.raises(TypeError):
            from_list(from_int, [1, "2", 3])

    def test_from_float_valid(self) -> None:
        """Tests that `from_float` correctly converts valid float and int values."""
        self.assertEqual(from_float(1.23), 1.23)

    def test_from_float_invalid(self) -> None:
        """Tests that `from_float` raises a TypeError for invalid types."""
        with pytest.raises(TypeError):
            from_float("hello")

    def test_from_bool_valid(self) -> None:
        """Tests that `from_bool` correctly converts a valid boolean value."""
        self.assertEqual(from_bool(True), True)  # noqa: FBT003
        self.assertEqual(from_bool(False), False)  # noqa: FBT003

    def test_from_bool_invalid(self) -> None:
        """Tests that `from_bool` raises a TypeError for an invalid type."""
        with pytest.raises(TypeError):
            from_bool("True")

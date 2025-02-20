"""Test the remote operation response object."""

import unittest
from uuid import UUID

import pytest

from mitsubishi_connect_client.remote_operation_response import RemoteOperationResponse

from . import remote_operation_response_test


class TestRemoteOperationResponse(unittest.TestCase):
    """Test the remote operation response object."""

    def test_from_dict(self) -> None:
        """Test the from_dict method."""
        obj = {
            "eventId": "59668d8a-6426-4691-b61b-3c87d206d3f9",
            "statusTimestamp": "2024-03-14T12:34:56.789Z",
            "startTime": "2024-03-14T12:34:56.789Z",
            "operationType": "engineOff",
            "vin": "1234567890ABCDEFG",
            "state": "1",
            "status": "success",
        }
        expected = RemoteOperationResponse(
            UUID("59668d8a-6426-4691-b61b-3c87d206d3f9"),
            "2024-03-14T12:34:56.789Z",
            "2024-03-14T12:34:56.789Z",
            "engineOff",
            "1234567890ABCDEFG",
            1,
            "success",
        )
        actual = RemoteOperationResponse.from_dict(obj)
        self.assertEqual(actual, expected)

        with pytest.raises(TypeError):
            RemoteOperationResponse.from_dict("invalid")  # type: ignore[arg-type]

    def test_from_text(self) -> None:
        """Test the from_text method."""
        response_text = remote_operation_response_test
        expected = RemoteOperationResponse(
            UUID("59668d8a-6426-4691-b61b-3c87d206d3f9"),
            "2024-03-14T12:34:56.789Z",
            "2024-03-14T12:34:56.789Z",
            "engineOff",
            "1234567890ABCDEFG",
            1,
            "success",
        )
        actual = RemoteOperationResponse.from_text(response_text)
        self.assertEqual(actual, expected)

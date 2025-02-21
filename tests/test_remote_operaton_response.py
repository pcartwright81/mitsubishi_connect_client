"""Test the remote operation response object."""

import unittest
from uuid import UUID

from mitsubishi_connect_client.remote_operation_response import RemoteOperationResponse

from . import remote_operation_response_test


class TestRemoteOperationResponse(unittest.TestCase):
    """Test the remote operation response object."""

    def test_from_text(self) -> None:
        """Test the from_text method."""
        response_text = remote_operation_response_test
        response = RemoteOperationResponse.from_text(response_text)
        self.assertEqual(
            response.event_id, UUID("59668d8a-6426-4691-b61b-3c87d206d3f9")
        )
        self.assertEqual(response.status_timestamp, "2024-03-14T12:34:56.789Z")
        self.assertEqual(response.start_time, "2024-03-14T12:34:56.789Z")
        self.assertEqual(response.operation_type, "engineOff")
        self.assertEqual(response.vin, "1234567890ABCDEFG")
        self.assertEqual(response.state, "1")
        self.assertEqual(response.status, "success")

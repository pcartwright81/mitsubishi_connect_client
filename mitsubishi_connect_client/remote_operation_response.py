"""Define a remote operation response object."""

import json
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from mitsubishi_connect_client import from_str


@dataclass
class RemoteOperationResponse:
    """The remote operation response."""

    event_id: UUID
    status_timestamp: str
    start_time: str
    operation_type: str
    vin: str
    state: int
    status: str

    @staticmethod
    def from_dict(obj: Any) -> "RemoteOperationResponse":
        """Convert a dict to an object."""
        if not isinstance(obj, dict):
            msg = f"Expected dict, got {type(obj)}"
            raise TypeError(msg)
        event_id = UUID(obj.get("eventId"))
        status_timestamp = from_str(obj.get("statusTimestamp"))
        start_time = from_str(obj.get("startTime"))
        operation_type = from_str(obj.get("operationType"))
        vin = from_str(obj.get("vin"))
        state = int(from_str(obj.get("state")))
        status = from_str(obj.get("status"))
        return RemoteOperationResponse(
            event_id, status_timestamp, start_time, operation_type, vin, state, status
        )

    @staticmethod
    def from_text(response_text: str) -> "RemoteOperationResponse":
        """Parse text to the object."""
        data = json.loads(response_text)
        return RemoteOperationResponse.from_dict(data)

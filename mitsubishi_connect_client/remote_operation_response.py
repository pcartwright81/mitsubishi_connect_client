"""Define a remote operation response object."""

from __future__ import annotations

from uuid import UUID  # noqa: TC003 needed for pydantic

from pydantic import BaseModel, Field


class RemoteOperationResponse(BaseModel):
    """Define a remote operation response object."""

    event_id: UUID = Field(..., alias="eventId")
    status_timestamp: str = Field(..., alias="statusTimestamp")
    start_time: str = Field(..., alias="startTime")
    operation_type: str = Field(..., alias="operationType")
    vin: str
    state: str
    status: str

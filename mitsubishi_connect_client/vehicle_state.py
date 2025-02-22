"""Define a vehicle state object."""

from __future__ import annotations

from datetime import datetime  # noqa: TC003 needed for pydantic

from pydantic import BaseModel, Field


class ExtLocMap(BaseModel):
    """Define an ext loc map object."""

    lon: float
    lat: float
    ts: datetime


class ChargingControl(BaseModel):
    """Define a charging control object."""

    cruising_range_combined: str = Field(..., alias="cruisingRangeCombined")
    event_timestamp: datetime = Field(..., alias="eventTimestamp")


class State(BaseModel):
    """Define a state object."""

    ext_loc_map: ExtLocMap = Field(..., alias="extLocMap")
    cst: bool
    tu_state: bool = Field(..., alias="tuState")
    ods: bool
    ignition_state: bool = Field(..., alias="ignitionState")
    odo: list[dict[datetime, int]]
    theft_alarm: bool = Field(..., alias="theftAlarm")
    svla: bool
    svtb: bool
    diagnostic: bool
    privacy: bool
    temp: str
    factory_reset: bool = Field(..., alias="factoryReset")
    tu_state_ts: datetime = Field(..., alias="tuStateTS")
    ignition_state_ts: datetime | None = Field(None, alias="ignitionStateTs")
    timezone: str
    accessible: bool
    charging_control: ChargingControl = Field(..., alias="chargingControl")


class VehicleState(BaseModel):
    """Define a vehicle state object."""

    vin: str
    ts: datetime
    state: State

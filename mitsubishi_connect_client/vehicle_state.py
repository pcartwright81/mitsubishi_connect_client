"""Define a vehicle state object."""

import json
from datetime import datetime
from typing import Any

from attr import dataclass

from mitsubishi_connect_client import (
    from_bool,
    from_datetime,
    from_float,
    from_str,
)


@dataclass
class EXTLOCMap:
    """The location on the map."""

    lon: float
    lat: float
    ts: int

    @staticmethod
    def from_dict(obj: Any) -> "EXTLOCMap":
        """Convert a dict to an object."""
        if not isinstance(obj, dict):
            msg = f"Expected dict, got {type(obj)}"
            raise TypeError(msg)
        lon = from_float(obj.get("lon"))
        lat = from_float(obj.get("lat"))
        ts = int(from_str(obj.get("ts")))
        return EXTLOCMap(lon, lat, ts)


@dataclass
class ChargingControl:
    """The charging control."""

    cruising_range_combined: str
    event_timestamp: int

    @staticmethod
    def from_dict(obj: Any) -> "ChargingControl":
        """Convert a dict to an object."""
        if not isinstance(obj, dict):
            msg = f"Expected dict, got {type(obj)}"
            raise TypeError(msg)
        cruising_range_combined = from_str(obj.get("cruisingRangeCombined"))
        event_timestamp = int(from_str(obj.get("eventTimestamp")))
        return ChargingControl(cruising_range_combined, event_timestamp)


@dataclass
class State:
    """The state of the vehicle."""

    ext_loc_map: EXTLOCMap
    cst: int
    tu_state: int
    ods: int
    ignition_state: int
    odo: list[dict[datetime, str]]
    theft_alarm: str
    svla: int
    svtb: int
    diagnostic: int
    privacy: int
    temp: int
    factory_reset: int
    tu_state_ts: str
    ignition_state_ts: str
    timezone: str
    accessible: bool
    charging_control: ChargingControl

    @staticmethod
    def from_dict(obj: Any) -> "State":
        """Convert a dict to an object."""
        if not isinstance(obj, dict):
            msg = f"Expected dict, got {type(obj)}"
            raise TypeError(msg)
        ext_loc_map = EXTLOCMap.from_dict(obj.get("extLocMap"))
        cst = int(from_str(obj.get("cst")))
        tu_state = int(from_str(obj.get("tuState")))
        ods = int(from_str(obj.get("ods")))
        ignition_state = int(from_str(obj.get("ignitionState")))
        odo = obj.get("odo")
        theft_alarm = from_str(obj.get("theftAlarm"))
        svla = int(from_str(obj.get("svla")))
        svtb = int(from_str(obj.get("svtb")))
        diagnostic = int(from_str(obj.get("diagnostic")))
        privacy = int(from_str(obj.get("privacy")))
        temp = int(from_str(obj.get("temp")))
        factory_reset = int(from_str(obj.get("factoryReset")))
        tu_state_ts = from_str(obj.get("tuStateTS"))
        ignition_state_ts = from_str(obj.get("ignitionStateTs"))
        timezone = from_str(obj.get("timezone"))
        accessible = from_bool(obj.get("accessible"))
        charging_control = ChargingControl.from_dict(obj.get("chargingControl"))
        return State(
            ext_loc_map,
            cst,
            tu_state,
            ods,
            ignition_state,
            odo,  # type: ignore[attr-defined]
            theft_alarm,
            svla,
            svtb,
            diagnostic,
            privacy,
            temp,
            factory_reset,
            tu_state_ts,
            ignition_state_ts,
            timezone,
            accessible,
            charging_control,
        )


@dataclass
class VehicleState:
    """The state of the vehicle."""

    vin: str
    ts: datetime
    state: State

    @staticmethod
    def from_text(response_text: str) -> "VehicleState":
        """Parse text to the object."""
        data = json.loads(response_text)
        vin = from_str(data.get("vin"))
        ts = from_datetime(data.get("ts"))
        state = State.from_dict(data.get("state"))
        return VehicleState(vin, ts, state)

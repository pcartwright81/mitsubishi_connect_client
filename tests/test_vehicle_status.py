"""Test the vehicle state object."""

import unittest
from datetime import UTC, datetime

from mitsubishi_connect_client.vehicle_state import (
    ChargingControl,
    ExtLocMap,
    State,
    VehicleState,
)


class TestVehicleState(unittest.TestCase):
    """Test the vehicle state object."""

    def test_ext_loc_map(self) -> None:
        """Test the ExtLocMap model."""
        data = {"lon": 123.456, "lat": 456.789, "ts": "2023-03-15T13:20:00Z"}
        ext_loc_map = ExtLocMap(**data)
        self.assertEqual(ext_loc_map.lon, 123.456)
        self.assertEqual(ext_loc_map.lat, 456.789)
        self.assertEqual(ext_loc_map.ts, datetime(2023, 3, 15, 13, 20, tzinfo=UTC))

    def test_charging_control(self) -> None:
        """Test the ChargingControl model."""
        data = {
            "cruisingRangeCombined": "200",
            "eventTimestamp": "2023-03-15T13:20:00Z",
        }
        charging_control = ChargingControl(**data)  # type: ignore This is a unit test.
        self.assertEqual(charging_control.cruising_range_combined, "200")
        self.assertEqual(
            charging_control.event_timestamp, datetime(2023, 3, 15, 13, 20, tzinfo=UTC)
        )

    def test_state(self) -> None:
        """Test the State model."""
        ext_loc_map_data = {
            "lon": 123.456,
            "lat": 456.789,
            "ts": "2023-03-15T13:20:00Z",
        }
        charging_control_data = {
            "cruisingRangeCombined": "200",
            "eventTimestamp": "2023-03-15T13:20:00Z",
        }
        data = {
            "extLocMap": ext_loc_map_data,
            "cst": "1",
            "tuState": "1",
            "ods": "0",
            "ignitionState": "0",
            "odo": [{"2025-02-09 15:14:49": "1223"}, {"2025-02-10 20:54:33": "1242"}],
            "theftAlarm": "OFF",
            "svla": "0",
            "svtb": "0",
            "diagnostic": "0",
            "privacy": "0",
            "temp": "1",
            "factoryReset": "0",
            "tuStateTS": "2025-02-22T15:12:11.691Z",
            "ignitionStateTs": "2025-02-22T09:15:49.354Z",
            "timezone": "UTC",
            "accessible": True,
            "chargingControl": charging_control_data,
        }

        state = State(**data)
        self.assertEqual(state.ext_loc_map.lon, 123.456)
        self.assertEqual(state.ext_loc_map.lat, 456.789)
        self.assertEqual(
            state.ext_loc_map.ts, datetime(2023, 3, 15, 13, 20, tzinfo=UTC)
        )
        self.assertEqual(state.cst, True)
        self.assertEqual(state.tu_state, True)
        self.assertEqual(state.ods, False)
        self.assertEqual(state.ignition_state, False)
        self.assertEqual(
            state.odo,
            [
                {datetime(2025, 2, 9, 15, 14, 49): 1223},  # noqa: DTZ001
                {datetime(2025, 2, 10, 20, 54, 33): 1242},  # noqa: DTZ001
            ],
        )
        self.assertEqual(state.theft_alarm, False)
        self.assertEqual(state.svla, False)
        self.assertEqual(state.svtb, False)
        self.assertEqual(state.diagnostic, False)
        self.assertEqual(state.privacy, False)
        self.assertEqual(state.temp, "1")
        self.assertEqual(state.factory_reset, False)
        self.assertEqual(
            state.tu_state_ts, datetime(2025, 2, 22, 15, 12, 11, 691000, tzinfo=UTC)
        )
        self.assertEqual(
            state.ignition_state_ts,
            datetime(2025, 2, 22, 9, 15, 49, 354000, tzinfo=UTC),
        )
        self.assertEqual(state.timezone, "UTC")
        self.assertEqual(state.accessible, True)
        self.assertEqual(state.charging_control.cruising_range_combined, "200")
        self.assertEqual(
            state.charging_control.event_timestamp,
            datetime(2023, 3, 15, 13, 20, tzinfo=UTC),
        )

    def test_state_with_none_ignition_state_ts(self) -> None:
        """Test the State model when ignition_state_ts is none."""
        ext_loc_map_data = {
            "lon": 123.456,
            "lat": 456.789,
            "ts": "2023-03-15T13:20:00Z",
        }
        charging_control_data = {
            "cruisingRangeCombined": "200",
            "eventTimestamp": "2023-03-15T13:20:00Z",
        }
        data = {
            "extLocMap": ext_loc_map_data,
            "cst": "1",
            "tuState": "1",
            "ods": "0",
            "ignitionState": "0",
            "odo": [{"2025-02-09 15:14:49": "1223"}, {"2025-02-10 20:54:33": "1242"}],
            "theftAlarm": "OFF",
            "svla": "0",
            "svtb": "0",
            "diagnostic": "0",
            "privacy": "0",
            "temp": "1",
            "factoryReset": "0",
            "tuStateTS": "2025-02-22T15:12:11.691Z",
            "ignitionStateTs": None,
            "timezone": "UTC",
            "accessible": True,
            "chargingControl": charging_control_data,
        }
        state = State(**data)
        self.assertEqual(state.ignition_state_ts, None)

    def test_vehicle_state(self) -> None:
        """Test the VehicleState model."""
        ext_loc_map_data = {
            "lon": 123.456,
            "lat": 456.789,
            "ts": "2023-03-15T13:20:00Z",
        }
        charging_control_data = {
            "cruisingRangeCombined": "200",
            "eventTimestamp": "2023-03-15T13:20:00Z",
        }
        state_data = {
            "extLocMap": ext_loc_map_data,
            "cst": "1",
            "tuState": "1",
            "ods": "0",
            "ignitionState": "0",
            "odo": [{"2025-02-09 15:14:49": "1223"}, {"2025-02-10 20:54:33": "1242"}],
            "theftAlarm": "OFF",
            "svla": "0",
            "svtb": "0",
            "diagnostic": "0",
            "privacy": "0",
            "temp": "1",
            "factoryReset": "0",
            "tuStateTS": "2025-02-22T15:12:11.691Z",
            "ignitionStateTs": "2025-02-22T09:15:49.354Z",
            "timezone": "UTC",
            "accessible": True,
            "chargingControl": charging_control_data,
        }
        data = {
            "vin": "1234567890ABCDEFG",
            "ts": "2024-03-14T12:34:56.789Z",
            "state": state_data,
        }
        vehicle_state = VehicleState(**data)
        self.assertEqual(vehicle_state.vin, "1234567890ABCDEFG")
        self.assertEqual(
            vehicle_state.ts, datetime(2024, 3, 14, 12, 34, 56, 789000, tzinfo=UTC)
        )
        self.assertEqual(vehicle_state.state.ext_loc_map.lon, 123.456)
        self.assertEqual(vehicle_state.state.ext_loc_map.lat, 456.789)
        self.assertEqual(
            vehicle_state.state.ext_loc_map.ts,
            datetime(2023, 3, 15, 13, 20, tzinfo=UTC),
        )
        self.assertEqual(vehicle_state.state.cst, True)
        self.assertEqual(vehicle_state.state.tu_state, True)
        self.assertEqual(vehicle_state.state.ods, False)
        self.assertEqual(vehicle_state.state.ignition_state, False)
        self.assertEqual(
            vehicle_state.state.odo,
            [
                {datetime(2025, 2, 9, 15, 14, 49): 1223},  # noqa: DTZ001
                {datetime(2025, 2, 10, 20, 54, 33): 1242},  # noqa: DTZ001
            ],
        )
        self.assertEqual(vehicle_state.state.theft_alarm, False)
        self.assertEqual(vehicle_state.state.svla, False)
        self.assertEqual(vehicle_state.state.svtb, False)
        self.assertEqual(vehicle_state.state.diagnostic, False)
        self.assertEqual(vehicle_state.state.privacy, False)
        self.assertEqual(vehicle_state.state.temp, "1")
        self.assertEqual(vehicle_state.state.factory_reset, False)
        self.assertEqual(
            vehicle_state.state.tu_state_ts,
            datetime(2025, 2, 22, 15, 12, 11, 691000, tzinfo=UTC),
        )
        self.assertEqual(
            vehicle_state.state.ignition_state_ts,
            datetime(2025, 2, 22, 9, 15, 49, 354000, tzinfo=UTC),
        )
        self.assertEqual(vehicle_state.state.timezone, "UTC")
        self.assertEqual(vehicle_state.state.accessible, True)
        self.assertEqual(
            vehicle_state.state.charging_control.cruising_range_combined, "200"
        )
        self.assertEqual(
            vehicle_state.state.charging_control.event_timestamp,
            datetime(2023, 3, 15, 13, 20, tzinfo=UTC),
        )

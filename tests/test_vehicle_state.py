"""Test the vehicle state object."""

import unittest
from datetime import UTC, datetime

import pytest

from mitsubishi_connect_client import vehicle_state

from . import test_vehicle_state_response


class TestVehicleState(unittest.TestCase):
    """Test the vehicle state object."""

    def test_extlocmap_from_dict(self) -> None:
        """Test the EXTLOCMap.from_dict method."""
        obj = {"lon": 123.456, "lat": 456.789, "ts": "1678886400000"}
        expected = vehicle_state.EXTLOCMap(123.456, 456.789, 1678886400000)
        actual = vehicle_state.EXTLOCMap.from_dict(obj)
        self.assertEqual(actual, expected)

        with pytest.raises(TypeError):
            vehicle_state.EXTLOCMap.from_dict("invalid")

    def test_chargingcontrol_from_dict(self) -> None:
        """Test the ChargingControl.from_dict method."""
        obj = {"cruisingRangeCombined": "200", "eventTimestamp": "1678886400000"}
        expected = vehicle_state.ChargingControl("200", 1678886400000)
        actual = vehicle_state.ChargingControl.from_dict(obj)
        self.assertEqual(actual, expected)

        with pytest.raises(TypeError):
            vehicle_state.ChargingControl.from_dict("invalid")

    def test_state_from_dict(self) -> None:
        """Test the State.from_dict method."""
        obj = {
            "extLocMap": {"lon": 123.456, "lat": 456.789, "ts": "1678886400000"},
            "cst": "1",
            "tuState": "2",
            "ods": "3",
            "ignitionState": "4",
            "odo": [{"2025-02-09 15:14:49": "1223"}, {"2025-02-10 20:54:33": "1242"}],
            "theftAlarm": "5",
            "svla": "6",
            "svtb": "7",
            "diagnostic": "8",
            "privacy": "9",
            "temp": "10",
            "factoryReset": "11",
            "tuStateTS": "12",
            "ignitionStateTs": "13",
            "timezone": "America/New_York",
            "accessible": True,
            "chargingControl": {
                "cruisingRangeCombined": "200",
                "eventTimestamp": "1678886400000",
            },
        }
        ext_loc_map = vehicle_state.EXTLOCMap(123.456, 456.789, 1678886400000)
        charging_control = vehicle_state.ChargingControl("200", 1678886400000)
        expected = vehicle_state.State(
            ext_loc_map,
            1,
            2,
            3,
            4,
            obj.get("odo"),  # type: ignore[attr-defined]
            "5",
            6,
            7,
            8,
            9,
            10,
            11,
            "12",
            "13",
            "America/New_York",
            True,  # noqa: FBT003
            charging_control,
        )
        actual = vehicle_state.State.from_dict(obj)
        self.assertEqual(actual, expected)

        with pytest.raises(TypeError):
            vehicle_state.State.from_dict("invalid")

    def test_vehiclestate_from_text(self) -> None:
        """Test the VehicleState.from_text method."""
        response_text = test_vehicle_state_response

        expected_ts = datetime(2024, 3, 14, 12, 34, 56, 789000, tzinfo=UTC)
        actual = vehicle_state.VehicleState.from_text(response_text)

        self.assertEqual(actual.vin, "1234567890ABCDEFG")
        self.assertEqual(actual.ts, expected_ts)

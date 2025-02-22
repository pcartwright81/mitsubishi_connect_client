"""Test the vehicle state object."""

import unittest
from datetime import UTC, datetime

from mitsubishi_connect_client.vehicle_state import VehicleState

from . import sample_vehicle_state


class TestVehicleState(unittest.TestCase):
    """Test the vehicle state object."""

    def test_vehiclestate_from_text(self) -> None:
        """Test VehicleState.from_text."""
        vehicle_state = VehicleState(**sample_vehicle_state)

        self.assertEqual(vehicle_state.vin, "1234567890ABCDEFG")
        self.assertEqual(
            vehicle_state.ts,
            datetime(2024, 3, 14, 12, 34, 56, 789000, tzinfo=UTC),
        )

        ext_loc_map = vehicle_state.state.ext_loc_map
        self.assertEqual(ext_loc_map.lon, 123.456)
        self.assertEqual(ext_loc_map.lat, 456.789)
        self.assertEqual(ext_loc_map.ts, datetime(2023, 3, 15, 13, 20, tzinfo=UTC))

        charging_control = vehicle_state.state.charging_control
        self.assertEqual(charging_control.cruising_range_combined, "200")
        self.assertEqual(
            charging_control.event_timestamp,
            datetime(2023, 3, 15, 13, 20, tzinfo=UTC),
        )

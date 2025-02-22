"""Test the vehicle object."""

import json
import unittest
from datetime import date

from mitsubishi_connect_client.vehicle import VechiclesResponse

from . import sample_vehicle


class TestVehiclesResponse(unittest.TestCase):
    """Test the vehicles response object."""

    def test_parsing(self) -> None:
        """Test the from_text method."""
        loaded = json.loads(json.dumps(sample_vehicle))
        vehicles_response = VechiclesResponse(**loaded)
        self.assertEqual(len(vehicles_response.vehicles), 1)
        self.assertEqual(vehicles_response.vehicles[0].vin, "vin")
        vehicle = vehicles_response.vehicles[0]
        self.assertEqual(vehicle.vin, "vin")
        self.assertEqual(
            vehicle.date_of_sale,
            date(2024, 12, 29),
        )
        self.assertEqual(vehicle.primary_user, True)
        self.assertEqual(vehicle.make, "make")
        self.assertEqual(vehicle.model, "model")
        self.assertEqual(vehicle.year, 2024)
        self.assertEqual(vehicle.exterior_color_code, "exteriorColorCode")
        self.assertEqual(vehicle.exterior_color, "exteriorColor")
        self.assertEqual(vehicle.sim_state, "simState")
        self.assertEqual(vehicle.model_description, "modelDescription")
        self.assertEqual(vehicle.country, "country")
        self.assertEqual(vehicle.region, "region")
        self.assertEqual(vehicle.alpha_three_country_code, "alphaThreeCountryCode")
        self.assertEqual(vehicle.country_name, "countryName")
        self.assertEqual(vehicle.is_fleet, False)

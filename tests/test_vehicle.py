"""Test the vehicle object."""

import unittest
from datetime import date

from mitsubishi_connect_client.vehicle import VechiclesResponse, Vehicle

from . import test_vehicles_response


class TestVehicle(unittest.TestCase):
    """Test the vehicle object."""

    def test_from_dict(self) -> None:
        """Test the from_dict method."""
        obj = {
            "vin": "vin",
            "dateOfSale": "2024-12-29",
            "primaryUser": True,
            "make": "make",
            "model": "model",
            "year": "2024",
            "exteriorColorCode": "exteriorColorCode",
            "exteriorColor": "exteriorColor",
            "simState": "simState",
            "modelDescription": "modelDescription",
            "country": "country",
            "region": "region",
            "alphaThreeCountryCode": "alphaThreeCountryCode",
            "countryName": "countryName",
            "isFleet": False,
        }
        vehicle = Vehicle.from_dict(obj)
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


class TestVehiclesResponse(unittest.TestCase):
    """Test the vehicles response object."""

    def test_from_text(self) -> None:
        """Test the from_text method."""
        response_text = test_vehicles_response
        vehicles_response = VechiclesResponse.from_text(response_text)
        self.assertEqual(len(vehicles_response.vehicles), 1)
        self.assertEqual(vehicles_response.vehicles[0].vin, "vin")

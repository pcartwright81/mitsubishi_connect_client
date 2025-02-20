"""Define a vehicle obejct."""

import json
from dataclasses import dataclass
from datetime import date
from typing import Any

from . import from_bool, from_date, from_int, from_list, from_str


@dataclass
class Vehicle:
    """Define the properties of a vehicle."""

    vin: str
    date_of_sale: date
    primary_user: bool
    make: str
    model: str
    year: int
    exterior_color_code: str
    exterior_color: str
    sim_state: str
    model_description: str
    country: str
    region: str
    alpha_three_country_code: str
    country_name: str
    is_fleet: bool

    @staticmethod
    def from_dict(obj: Any) -> "Vehicle":
        """Convert a dict to an object."""
        vin = from_str(obj.get("vin"))
        date_of_sale = from_date(obj.get("dateOfSale"))
        primary_user = from_bool(obj.get("primaryUser"))
        make = from_str(obj.get("make"))
        model = from_str(obj.get("model"))
        year = from_int(obj.get("year"))
        exterior_color_code = from_str(obj.get("exteriorColorCode"))
        exterior_color = from_str(obj.get("exteriorColor"))
        sim_state = from_str(obj.get("simState"))
        model_description = from_str(obj.get("modelDescription"))
        country = from_str(obj.get("country"))
        region = from_str(obj.get("region"))
        alpha_three_country_code = from_str(obj.get("alphaThreeCountryCode"))
        country_name = from_str(obj.get("countryName"))
        is_fleet = from_bool(obj.get("isFleet"))
        return Vehicle(
            vin,
            date_of_sale,
            primary_user,
            make,
            model,
            year,
            exterior_color_code,
            exterior_color,
            sim_state,
            model_description,
            country,
            region,
            alpha_three_country_code,
            country_name,
            is_fleet,
        )


@dataclass
class VechiclesResponse:
    """Represent a vehicle response from the api."""

    vehicles: list[Vehicle]

    @staticmethod
    def from_text(response_text: str) -> "VechiclesResponse":
        """Parse text to the object."""
        data = json.loads(response_text)
        vehicles = from_list(Vehicle.from_dict, data.get("vehicles"))
        return VechiclesResponse(vehicles)

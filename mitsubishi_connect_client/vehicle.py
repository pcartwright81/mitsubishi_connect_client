"""Define a vehicle object."""

from __future__ import annotations

from datetime import date  # noqa: TC003 needed for pydantic

from pydantic import BaseModel, Field


class Vehicle(BaseModel):
    """Define a vehicle object."""

    vin: str
    date_of_sale: date = Field(..., alias="dateOfSale")
    primary_user: bool = Field(..., alias="primaryUser")
    make: str
    model: str
    year: int
    exterior_color_code: str = Field(..., alias="exteriorColorCode")
    exterior_color: str = Field(..., alias="exteriorColor")
    sim_state: str = Field(..., alias="simState")
    model_description: str = Field(..., alias="modelDescription")
    country: str
    region: str
    alpha_three_country_code: str = Field(..., alias="alphaThreeCountryCode")
    country_name: str = Field(..., alias="countryName")
    is_fleet: bool = Field(..., alias="isFleet")


class VechiclesResponse(BaseModel):
    """Define a vehicles response object."""

    vehicles: list[Vehicle]

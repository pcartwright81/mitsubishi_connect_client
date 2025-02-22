"""Define a vehicle status object."""

from __future__ import annotations

from pydantic import BaseModel, Field


class BreakWarn(BaseModel):
    """Define a break warn object."""

    name: str
    display_message: str = Field(..., alias="displayMessage")
    value: str
    warning: bool


class Odos(BaseModel):
    """Define an odo object."""

    name: str
    display_message: str = Field(..., alias="displayMessage")
    value: str


class EngineOilWarn(BaseModel):
    """Define an engine oil warn object."""

    name: str
    display_message: str = Field(..., alias="displayMessage")
    value: str
    warning: bool


class TireStatus(BaseModel):
    """Define a tire status object."""

    name: str
    display_message: str = Field(..., alias="displayMessage")
    value: str
    warning: bool


class AvailRange(BaseModel):
    """Define an avail range object."""

    name: str
    display_message: str = Field(..., alias="displayMessage")
    value: str


class Odo(BaseModel):
    """Define an odo object."""

    name: str
    display_message: str = Field(..., alias="displayMessage")
    value: str


class Spd(BaseModel):
    """Define a spd object."""

    name: str
    display_message: str = Field(..., alias="displayMessage")
    value: str


class Igst(BaseModel):
    """Define an igst object."""

    name: str
    display_message: str = Field(..., alias="displayMessage")
    value: str


class Diagnostic(BaseModel):
    """Define a diagnostic object."""

    break_warn: BreakWarn = Field(..., alias="breakWarn")
    odos: Odos
    engine_oil_warn: EngineOilWarn = Field(..., alias="engineOilWarn")
    digsts: str
    tire_status: TireStatus = Field(..., alias="tireStatus")
    avail_range: AvailRange = Field(..., alias="availRange")
    odo: Odo
    spd: Spd
    igst: Igst


class Position(BaseModel):
    """Define a position object."""

    name: str
    display_message: str = Field(..., alias="displayMessage")
    value: str


class State(BaseModel):
    """Define a state object."""

    name: str
    display_message: str = Field(..., alias="displayMessage")
    value: str


class Door(BaseModel):
    """Define a door object."""

    position: Position
    state: State


class DoorStatus(BaseModel):
    """Define a door status object."""

    id: str
    name: str
    doors: list[Door]


class State1(BaseModel):
    """Define a state1 object."""

    name: str
    display_message: str = Field(..., alias="displayMessage")
    value: str


class Position1(BaseModel):
    """Define a position1 object."""

    name: str
    display_message: str = Field(..., alias="displayMessage")
    value: str


class Light(BaseModel):
    """Define a light object."""

    state: State1
    position: Position1


class LightStatus(BaseModel):
    """Define a light status object."""

    id: str
    name: str
    lights: list[Light]


class VehicleStatus(BaseModel):
    """Define a vehicle status object."""

    door_status: DoorStatus = Field(..., alias="doorStatus")
    light_status: LightStatus = Field(..., alias="lightStatus")


class Dt(BaseModel):
    """Define a dt object."""

    diagnostic: Diagnostic
    message: str
    vehicle_status: VehicleStatus = Field(..., alias="vehicleStatus")


class VhrItem(BaseModel):
    """Define a vhr item object."""

    cid: str
    vin: str
    operation: str
    ts: int
    dt: Dt


class VehicleStatusResponse(BaseModel):
    """Define a vehicle status response object."""

    vhr: list[VhrItem]

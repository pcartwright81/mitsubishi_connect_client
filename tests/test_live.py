"""Run a test against the live api."""

import os

import pytest

from mitsubishi_connect_client.mitsubishi_connect_client import MitsubishiConnectClient
from mitsubishi_connect_client.remote_operation_response import RemoteOperationResponse
from mitsubishi_connect_client.vehicle_state import VehicleState


@pytest.mark.skip(reason="Live testing disabled.")
async def test_async() -> None:
    """Run a test against the live api."""
    _username = os.environ["MITSUBISHI_USERNAME"]
    _password = os.environ["MITSUBISHI_PASSWORD"]
    _client = MitsubishiConnectClient(_username, _password)

    pin = os.environ["MITSUBISHI_PIN"]
    await _client.login()
    assert _client.token is not None

    vehicles_response = await _client.get_vehicles()
    assert len(vehicles_response.vehicles) > 0

    vehicle_state = await _client.get_vehicle_state(vehicles_response.vehicles[0].vin)
    assert isinstance(vehicle_state, VehicleState)

    pin_token = await _client.get_pin_token(vehicles_response.vehicles[0].vin, pin)
    assert isinstance(pin_token, str)

    response = await _client.unlock_vehicle(
        vehicles_response.vehicles[0].vin, pin_token
    )
    assert isinstance(response, RemoteOperationResponse)
